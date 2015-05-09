#!/bin/bash

set -eux

if [[ "${TRAVIS_BRANCH}" != 'master' ]] || [[ "${TRAVIS_PULL_REQUEST}" = 'true' ]]; then
   exit 0
fi

cargo doc

# Add an automatic redirect
repo_name=$(echo "${TRAVIS_REPO_SLUG}" | cut -d '/' -f 2 | sed 's/-/_/')
echo "<meta http-equiv=refresh content=0;url=${repo_name}/index.html>" > target/doc/index.html

rm -rf generated-documentation
mv target/doc generated-documentation

cd generated-documentation

git init
git config user.name "Travis-CI"
git config user.email "builder@travis"

git add .
git commit -m "Deployed to Github Pages"

set +x # Never print the token!
git push --force --quiet "https://${GH_TOKEN}@github.com/${TRAVIS_REPO_SLUG}" master:gh-pages
