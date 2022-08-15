module sha_round_constant_rom (
  input logic clk,
  input logic en,
  input logic [5:0] addr,
  output logic [31:0] data
);

logic [31:0] rom [0:63];

initial begin
  $readmemh("sha_round_constants.mem", rom);
end

always_ff @(posedge clk) begin
  if (en) data <= rom[addr];
end

endmodule
