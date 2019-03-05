#!/bin/sh

# tutorial: https://blog.packagecloud.io/eng/2016/12/15/howto-build-debian-package-containing-simple-shell-scripts/

# this script build deb package for coccoc-update-gsb4

# remove orig file; keep the directory
rm coccoc*orig*
mkdir -p coccoc-gsb4-0.1
cd coccoc-gsb4-0.1
dh_make --indep --createorig -y
cp ../install debian/
cp ../control debian/
cp ../coccoc-gsb4.cron.d debian/
debuild -us -uc