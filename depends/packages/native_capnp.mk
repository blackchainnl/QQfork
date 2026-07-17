package=native_capnp
$(package)_version=0.7.1
$(package)_download_path=https://capnproto.org/
$(package)_download_file=capnproto-c++-$($(package)_version).tar.gz
$(package)_file_name=capnproto-cxx-$($(package)_version).tar.gz
$(package)_sha256_hash=c510f93e40206dbf34133e1766aec04b98c3c54db53b243f15e1712d1b1352cd

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
