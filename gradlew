#!/bin/sh
# Gradle wrapper script for Unix

APP_NAME="Gradle"
APP_BASE_NAME=$(basename "$0")

# Default JVM options
DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'

# Attempt to find JAVA_HOME
if [ -z "$JAVA_HOME" ] ; then
    if [ -r /etc/gentoo-release ] ; then
        JAVA_HOME=$(java-config --jre-home)
    fi
fi

# Increase the maximum file descriptors
MAX_FD="maximum"

warn () {
    echo "$*"
}

die () {
    echo
    echo "$*"
    echo
    exit 1
}

# OS specific support
cygwin=false
msys=false
darwin=false
nonstop=false

case "$(uname)" in
  CYGWIN* ) cygwin=true ;;
  Darwin*  ) darwin=true ;;
  MSYS*    ) msys=true ;;
  NONSTOP* ) nonstop=true ;;
esac

CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"

if [ -n "$JAVA_HOME" ] ; then
    if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
        JAVACMD="$JAVA_HOME/jre/sh/java"
    else
        JAVACMD="$JAVA_HOME/bin/java"
    fi
    if [ ! -x "$JAVACMD" ] ; then
        die "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME"
    fi
else
    JAVACMD="java"
    which java >/dev/null 2>&1 || die "ERROR: JAVA_HOME is not set and no 'java' command could be found."
fi

APP_HOME=$(cd "$(dirname "$0")" && pwd -P)

exec "$JAVACMD" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain \
    "$@"