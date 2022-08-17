# Clock is 250 MHz
create_clock -period 4.000 ns -name clk -waveform {0 2.000} [get_ports clk]
