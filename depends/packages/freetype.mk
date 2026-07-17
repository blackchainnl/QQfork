package=freetype
$(package)_version=2.14.3
$(package)_download_path=https://download.savannah.gnu.org/releases/$(package)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f
$(package)_patches=disable_refdoc_warning.patch

define $(package)_set_vars
  $(package)_config_opts=--without-zlib --without-png --without-harfbuzz --without-bzip2 --disable-static
  $(package)_config_opts += --enable-option-checking --without-brotli
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/disable_refdoc_warning.patch
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share/man lib/*.la
endef
