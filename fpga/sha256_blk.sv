/**
 * sha256.sv - SHA-256 hash for one message block.
 *
 * Operation of each message block hash: 
 * NOTE: `pre-rounds` and `post-rounds` refer to before and after all 64
 * rounds, not before/after each individual round.
 *
 * pre-rounds: assign working vars, load msgblk, prefetch round constant.
 *
 * clk 0: Compute message schedule value (differs between rounds 0-15, 16-63).
 *        Shift working vars.
 *        Start computing T1 (with h, Sigma1, ch)
 *        Compute T2, shift in to working var stack.
 *
 * clk 1: Finish T1, add to e, a in working var reg.
 *        
 * post-rounds: Add working vars to hash reg.
 *              If last is true reset intermediate hash reg to init values
 */

// TODO: Define package for interfaces, types.
module sha256_blk (
  input logic clk,
  input logic arst_n,

  // Input data channel - Message block.
  // Use AXI Stream TLAST value to indicate last message block.
  input logic [511:0] axis_s_tdata,
  input logic axis_s_tvalid,
  input logic axis_s_tlast,
  output logic axis_s_tready,

  // Output data channel - Message digest.
  output logic [255:0] axis_m_tdata,
  output logic axis_m_tvalid,
  input logic axis_m_tready
);

// AXI Stream control signals.
logic axis_s_ok, axis_m_ok;
always_comb axis_s_ok = axis_s_tvalid && axis_s_tready;
always_comb axis_m_ok = axis_m_tvalid && axis_m_tready;

logic is_last_msg_blk;
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    is_last_msg_blk <= 0;
  end else begin
    is_last_msg_blk <= (axis_s_ok) ? axis_s_tlast : is_last_msg_blk;
  end
end

// SHA-256 FSM (states explained at top of file).
typedef enum {
  Idle,
  PreRounds,
  RoundClk0,
  RoundClk1,
  PostRounds
} state_t;
state_t state, next;

// State transitions.
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    state <= PreRounds;
  end else begin
    state <= next;
  end
end

// Next state assignment.
always_comb begin
  unique case (state)
    Idle: begin
      next = (axis_s_ok) ? PreRounds : Idle;
    end
    PreRounds: begin
      next = RoundClk0;
    end
    RoundClk0: begin
      next = RoundClk1;
    end
    RoundClk1: begin
      next = (&rnd_counter) ? PostRounds : RoundClk0;
    end
    PostRounds: begin
      // Stall here only if we're on last and !axis_m_ok.
      // O.w. we go to PreRounds if we have another axis_s_ok, or Idle if no
      // axis_s_ok, this is regardless of tlast value.
      next = (is_last_msg_blk && !axis_m_ok) ? PostRounds :
             (axis_s_ok) ? PreRounds : Idle;
    end
    default: begin
      next = state;
    end
  endcase
end

// State outputs: s_tready, m_tvalid.
always_comb begin
  unique case (state)
    Idle: begin
      axis_s_tready = 1;
      axis_m_tvalid = 0;
    end
    PreRounds: begin
      axis_s_tready = 0;
      axis_m_tvalid = 0;
    end
    RoundClk0: begin
      axis_s_tready = 0;
      axis_m_tvalid = 0;
    end
    RoundClk1: begin
      axis_s_tready = 0;
      axis_m_tvalid = 0;
    end
    PostRounds: begin
      axis_s_tready = (is_last_msg_blk) ? axis_m_tready : 1;
      axis_m_tvalid = is_last_msg_blk;
    end
    default: begin
      axis_s_tready = 0;
      axis_m_tvalid = 0;
    end
  endcase
end


// Declare intermediate nets.
logic [511:0] msgblk;
logic [7:0][31:0] intermediate_hash;  // Intermediate hash registers
logic [7:0][31:0] msg_digest;         // Final hash value.
logic [15:0][31:0] msg_schedule;      // Message schedule.
logic [15:0][3:0] msg_schedule_ptrs;
logic [7:0][31:0] work_vars;          // a-h, use shift reg w some adds.
logic [31:0] tmp1, tmp2;              // T1, T2 in code.

logic is_rnd_0_15;
logic [5:0] rnd_counter;  // 64 rounds

// Count each round.
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    rnd_counter <= 0;
  end else begin
    // Only start counting rounds when we get OK data.
    rnd_counter <= (state == RoundClk1) ? rnd_counter + 1 : rnd_counter;
  end
end

always_comb is_rnd_0_15 = ~&rnd_counter[5:4];

// TODO: Fetch SHA-256 `K` constants from BRAM. Total of 2^11 bits.
logic en;
logic [5:0] rnd_const_rom_addr;
logic [31:0] rnd_const;               // K value from FIPS.
sha_round_constant_rom rom_i (
  .clk (clk),
  .en  (en),
  .addr (rnd_const_rom_addr),
  .data (rnd_const)
);

// Drive ROM accesses.
always_comb begin
  en = 1;
  rnd_const_rom_addr = rnd_counter;
end

// Load msgblk into buffer.
// No reset bc we're just going to rely on control signals.
always_ff @(posedge clk) begin
  if (state == RoundClk1) begin
    msgblk <= msgblk << 32;
  end else begin
    msgblk <= (axis_s_ok) ? axis_s_tdata : msgblk;
  end
end

// Init message schedule pointer array order, circular rotate every round.
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    for (int i = 0; i < 16; i++) begin
      msg_schedule_ptrs[i] <= i;
    end
  end else begin
    if (state == RoundClk1) begin
      msg_schedule_ptrs <= { msg_schedule_ptrs[0], msg_schedule_ptrs[15:1] };
    end
  end
end

// TODO: Populate message schedule.
logic [31:0] s0, s1, msg_schedule_1, msg_schedule_14;
always_comb begin
  // To make things a bit less verbose.
  msg_schedule_1 = msg_schedule[msg_schedule_ptrs[1]];
  msg_schedule_14 = msg_schedule[msg_schedule_ptrs[14]];

  // Compute sigmas all inline.
  // NOTE: Worried about timing.
  // TODO: Check this actually meets timing.
  s0 = ({ msg_schedule_1[0 +: 7], msg_schedule_1[31 -: (32-7)] }) ^ ({ msg_schedule_1[0 +: 18], msg_schedule[31 -: (32-18)]}) ^ (msg_schedule_1 >> 3);  // sigma0(W[t + 1 mod 16])
  s1 = ({ msg_schedule_14[0 +: 17], msg_schedule_14[31 -: (32-17)] }) ^ ({ msg_schedule_14[0 +: 19], msg_schedule_14[31 -: (32-19)]}) ^ (msg_schedule_14 >> 10);  // sigma1(W[t + 14 mod 16])
end

always_ff @(posedge clk) begin
  if (state == RoundClk0) begin
    if (is_rnd_0_15) begin
      msg_schedule[msg_schedule_ptrs[0]] <= msgblk[511 -: 32];
    end else begin
      // TODO: Timing?
      msg_schedule[msg_schedule_ptrs[0]] <= s0 + s1 + msg_schedule[msg_schedule_ptrs[9]];
    end
  end
end

// TODO: Compute temp vars
// Compute Sigma1(e) and ch(e,f,g)
logic [31:0] e, f, g, ch, big_sigma1_e;
always_comb begin
  e = work_vars[4];
  f = work_vars[5];
  g = work_vars[6];

  ch = ((e & f) ^ (~e & g));
  big_sigma1_e = { e[0 +: 6], e[31 -: (32-6)] } ^ {e[0 +: 11], e[31 -: (32-11)] } ^ { e[0 +: 25], e[31 -: (32-25)] };
end


always_ff @(posedge clk) begin
  if (state == RoundClk0) begin
    // TODO: Timing?
    tmp1 <= work_vars[7] + big_sigma1_e + ch;
  end
end

logic [31:0] a, b, c;
always_comb begin
  // T2 = Sigma0(a) + maj(a, b, c)
  a = work_vars[0];
  b = work_vars[1];
  c = work_vars[2];
  tmp2 = (
    (a & b) ^ (a & c) ^ (b & c)
  ) + (
    {a[0 +: 2], a[31 -: (32-2)]} ^ {a[0 +: 13], a[31 -: (32-13)]} ^ {a[0 +: 22], a[31 -: (32-22)]}
  );
end

// Shift working vars, then add tmp vars to it.
always_ff @(posedge clk) begin
  if (state == PreRounds) begin
    // Init working vars.
    for (int i = 0; i < 8; i++) begin
      work_vars[i] <= intermediate_hash[i];
    end
  end else if (state == RoundClk0) begin
    // Shift in T2.
    work_vars <= { work_vars[6:0], tmp2 };
  end else if (state == RoundClk1) begin
    // Finish the adds.
    // TODO: Timing?
    work_vars[0] <= work_vars[0] + tmp1 + msg_schedule[msg_schedule_ptrs[0]] + rnd_const;
    work_vars[4] <= work_vars[4] + tmp1 + msg_schedule[msg_schedule_ptrs[0]] + rnd_const;
  end
end

// Increment hash values.
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    intermediate_hash[0] <= 32'h6a09e667;
    intermediate_hash[1] <= 32'hbb67ae85;
    intermediate_hash[2] <= 32'h3c6ef372;
    intermediate_hash[3] <= 32'ha54ff53a;
    intermediate_hash[4] <= 32'h510e527f;
    intermediate_hash[5] <= 32'h9b05688c;
    intermediate_hash[6] <= 32'h1f83d9ab;
    intermediate_hash[7] <= 32'h5be0cd19;
  end else begin
    if (state == PostRounds) begin
      if (is_last_msg_blk) begin
        intermediate_hash[0] <= 32'h6a09e667;
        intermediate_hash[1] <= 32'hbb67ae85;
        intermediate_hash[2] <= 32'h3c6ef372;
        intermediate_hash[3] <= 32'ha54ff53a;
        intermediate_hash[4] <= 32'h510e527f;
        intermediate_hash[5] <= 32'h9b05688c;
        intermediate_hash[6] <= 32'h1f83d9ab;
        intermediate_hash[7] <= 32'h5be0cd19;
      end else begin
        for (int i = 0; i < 8; i++) begin
          intermediate_hash[i] <= intermediate_hash[i] + work_vars[i];
        end
      end
    end
  end
end

// Set message digest after last message block.
always_ff @(posedge clk or negedge arst_n) begin
  if (!arst_n) begin
    msg_digest <= 0;
  end else begin
    if (state == PostRounds && is_last_msg_blk) begin
      for (int i = 0; i < 8; i++) begin
        msg_digest[i] <= intermediate_hash[i] + work_vars[i];
      end
    end
  end
end

always_comb axis_m_tdata = { msg_digest[0], msg_digest[1], msg_digest[2], msg_digest[3], msg_digest[4], msg_digest[5], msg_digest[6], msg_digest[7] };


endmodule
