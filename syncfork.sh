#!/bin/sh
fatal() {
  echo "$@" 2>&1
  exit 1
}

[ ! -d .git ] && fatal "No GIT repo!"

if ! git remote -v | grep upstream ; then
  echo Configuring upstream
  git remote add upstream https://github.com/proot-me/PRoot.git
fi
git fetch upstream
git merge upstream/master
