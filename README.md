# coccoc-gsb
This service is to update cache of prefix-hashes of unsafe resources provided by google https://developers.google.com/safe-browsing/v4/

# Build debian package
- Rename `src/main.yaml.ex` to `src/main.yaml` and fill api-key in `src/main.yaml`
- Dependencies
	- `liblog-log4perl-perl`
	- `libnet-google-safebrowsing4-perl` (1)
	- `libjson-streaming-writer-perl` (2)
	- `libyaml-perl`, 
	- `libparams-validate-perl`
- (1) (2) are not available though `apt` repositories (for now) so we need to manually build and install them first. Check prebuilt `libs/*deb` (`liblist-binarysearch-perl_0.25-1_all.deb` and `libnet-ip-lite-perl_0.03-1_all.deb` are required for manually-built `libnet-google-safebrowsing4-perl_0.8-1_all.deb`)
- Other dependencies will be automatically installed. 
- Build by `gsb4-deb/build.sh`. You might need to install tools (`debuild`, `dh_make`, etc) to make it works.
 
# Helpful config
- Maintainer's email: `gsb4-deb/coccoc-gsb4.cron.d` email will received mails when errors happen
