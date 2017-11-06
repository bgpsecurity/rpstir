docker volume create --name=mysqldatadir
mkdir -p  /root/dockervolume
mkdir -p /root/dockervolume/rpstir/cache  /root/dockervolume/rpstir/log
rm -rf /root/dockervolume/mysql
ln -s  /var/lib/docker/volumes/mysqldatadir/_data  /root/dockervolume/mysql
docker run -itd --privileged -p 13306:3306  -v mysqldatadir:/var/lib/mysql  -v /root/dockervolume/rpstir/cache:/usr/local/var/cache/rpstir  -v /root/dockervolume/rpstir/log:/usr/local/var/log/rpstir     -v /etc/localtime:/etc/localtime --name=rpstir_docker_centos6.9   rpstir/rpstir_docker_centos6.9 
sleep 2s
docker ps
