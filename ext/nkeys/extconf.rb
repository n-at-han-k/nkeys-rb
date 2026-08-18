# frozen_string_literal: true

require "mkmf"
require "rb_sys/mkmf"

# Builds the Rust crate in this directory and produces nkeys_rb.so.
# The crate's #[magnus::init] defines the classes under NKeys.
create_rust_makefile("nkeys_rb")
