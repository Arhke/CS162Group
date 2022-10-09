# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-not-child) begin
child-more: exit(0)
(wait-not-child) wait(exec()) = 0
(wait-not-child) end
wait-not-child: exit(0)
EOF
pass;
