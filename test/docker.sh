#!/bin/sh

# Install required packages with ./docker.sh packages
# Run ./docker.sh start
# Then ./docker.sh passwd until password is shown
# Then ./docker.sh connect, enter the password and run the two commands in the message
# ./docker.sh populate
# ./docker.sh yubiauth
# and finally in another shell ./docker.sh run to run tests

start() {
  rm -f /tmp/yubistack*
  docker rm -f mysql
  if ! docker top mysql &>/dev/null; then
    docker run --rm --name=mysql -p 3306:3306 -d mysql/mysql-server:5.7
  fi
}

packages() {
  sudo yum install blue-python36-mysqlclient blue-python36-yubistack uwsgi uwsgi-plugin-blue-python36
}

passwd() {
  while /bin/true; do
    p=$(docker logs mysql 2>/dev/null | grep ROOT | cut -d' ' -f5)
    [ ! -z "$p" ] && echo "$p" && break
  done
}

init() {
  local pass="$1"
  (
    echo "ALTER USER 'root'@'localhost' IDENTIFIED BY 'some_password';"
    echo "GRANT ALL ON *.* to root@'%' IDENTIFIED BY 'some_password';"
  ) | docker exec -i mysql mysql -uroot -p$pass --connect-expired-password
  return $?
}

connect() {
  docker exec -ti mysql mysql -uroot -p
}

populate() {
  (
    echo "CREATE DATABASE ykksm;"
    echo "USE ykksm;"
    cat assets/sql/sqlite/ykksm.sql

    echo "CREATE DATABASE ykval;"
    echo "USE ykval;"
    cat assets/sql/sqlite/ykval.sql

    echo "CREATE DATABASE yubiauth;"
    echo "USE yubiauth;"
    cat assets/sql/sqlite/ykauth.sql
  ) | mysql -uroot -psome_password -h0.0.0.0
}

all() {
  start
  while ! init $(passwd); do
    sleep 1
    echo "retrying init"
  done
  populate
}

cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/.."
[[ -z "$1" ]] && all || $@
