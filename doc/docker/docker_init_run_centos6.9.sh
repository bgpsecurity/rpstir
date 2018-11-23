docker volume create --name=mysqldatadir
mkdir -p  /root/dockervolume
mkdir -p /root/dockervolume/rpstir/cache /root/dockervolume/rpstir/cache-valid /root/dockervolume/rpstir/log
rm -rf /root/dockervolume/mysql
ln -s  /var/lib/docker/volumes/mysqldatadir/_data  /root/dockervolume/mysql
docker run -itd --privileged -p 13306:3306   -p 11234:1234 -v mysqldatadir:/var/lib/mysql  -v /root/dockervolume/rpstir/cache:/usr/local/var/cache/rpstir  -v /root/dockervolume/rpstir/log:/usr/local/var/log/rpstir  -v /root/dockervolume/rpstir/cache-valid:/usr/local/var/cache/rpstir-tmp   -v /etc/localtime:/etc/localtime --name=rpstir_docker_centos6.9   rpstir/rpstir_docker_centos6.9 
sleep 2s
docker ps
