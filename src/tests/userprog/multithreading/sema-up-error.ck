# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(sema-up-error) begin
sema-up-error: exit(1)
EOF
pass;
