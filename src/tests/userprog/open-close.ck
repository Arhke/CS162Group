# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(open-close) begin
(open-close) open "sample.txt" once
(open-close) open "sample.txt" again
(open-close) verified contents of "sample.txt"
(open-close) end
open-close: exit(0)
EOF
pass;
