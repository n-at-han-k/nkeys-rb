# frozen_string_literal: true

require "rb_sys/extensiontask"

GEMSPEC = Gem::Specification.load("nkeys-rb.gemspec")

# Compiles ext/nkeys (Rust/magnus) into lib/nkeys/nkeys_rb.so so
# `require "nkeys"` works.
#
# RbSys::ExtensionTask (instead of the plain Rake::ExtensionTask) wires up the
# rb-sys/oxidize-rb toolchain so we can *cross-compile* precompiled, per-platform
# native gems. That is what lets `gem install nkeys-rb` work WITHOUT Rust:
# RubyGems downloads the fat gem matching the platform (which already contains a
# prebuilt .so) instead of the source gem that shells out to cargo.
RbSys::ExtensionTask.new("nkeys_rb", GEMSPEC) do |ext|
  ext.ext_dir = "ext/nkeys"
  ext.lib_dir = "lib/nkeys"

  # Fat gems place the compiled object in a per-Ruby-version subdir
  # (lib/nkeys/3.3/, 3.4/, ...); lib/nkeys.rb requires it from there.
  ext.cross_compile = true
end

# Cross-compile a precompiled gem for one platform inside the rb-sys-dock
# container, e.g. `rake native[x86_64-linux]`. CI (cross-compile.yml) drives the
# full platform matrix via oxidize-rb/actions/cross-gem.
task :native, [:platform] do |_t, args|
  platform = args[:platform] or abort "usage: rake native[<platform>]"
  sh "bundle", "exec", "rb-sys-dock", "--platform", platform, "--build"
end

task default: :compile
