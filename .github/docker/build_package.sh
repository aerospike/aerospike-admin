
function build_packages(){
  if [ "$ENV_DISTRO" = "" ]; then
    echo "ENV_DISTRO is not set"
    return
  fi
  cd "$GIT_DIR"
  make one-file
  cd $PKG_DIR
  echo "building package for $BUILD_DISTRO"

  if [[ $ENV_DISTRO == *"ubuntu"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"debian"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"ubi"* ]]; then
    make rpm
  else
    make tar
  fi

  mkdir -p /tmp/output/$ENV_DISTRO
  cp -a $PKG_DIR/target/* /tmp/output/$ENV_DISTRO
}