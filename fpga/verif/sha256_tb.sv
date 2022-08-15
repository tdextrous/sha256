module sha256_tb;

// Generate clock.
logic clk;
initial clk = 0;
localparam CLK_HZ = 100_000_000;
always #(0.5s / CLK_HZ) clk = ~clk;

// Instantiate nets.
logic arst_n;

logic axis_s_tvalid, axis_s_tlast, axis_s_tready;
logic [511:0] axis_s_tdata;

logic axis_m_tvalid, axis_m_tready;
logic [255:0] axis_m_tdata;


// Instantiate DUT.
sha256_blk dut_i (
  .clk    (clk),
  .arst_n (arst_n),

  .axis_s_tdata   (axis_s_tdata),
  .axis_s_tvalid  (axis_s_tvalid),
  .axis_s_tlast   (axis_s_tlast),
  .axis_s_t_ready (axis_s_tready),

  .axis_m_tdata   (axis_m_tdata),
  .axis_m_tvalid  (axis_m_tvalid),
  .axis_m_t_ready (axis_m_tready)
);

// Drive a sample FIPS test vector, check output manually for now.
// TODO: Self checking testbench using DPI.
initial begin
  // Init nets.
  axis_s_tvalid = 0;
  axis_s_tlast = 0;
  axis_s_tdata = 0;
  axis_m_tready = 1;
  arst_n = 1;


  // Do reset.
  @(posedge clk);
  arst_n = 0;
  repeat (10) @(posedge clk);
  arst_n = 1;
  @(posedge clk);

  // Drive data.
  @(posedge clk);
  axis_s_tvalid = 1;
  axis_s_tlast = 1;
  axis_s_tdata = 512'h61626380_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000018;  // "abc"
  while (!axis_s_tready) @(posedge clk);
  @(posedge clk);

  // cleanup inputs.
  axis_s_tvalid = 0;
  axis_s_tlast = 0;
  @(posedge clk);

  // Wait for response.
  while (!axis_m_tvalid) @(posedge clk);
  @(posedge clk);


  $finish;
end

endmodule
