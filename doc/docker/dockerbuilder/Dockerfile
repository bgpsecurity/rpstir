# Version 1.0
# Comment rpstir on centos6.9
FROM docker.io/centos:6.9

# copy needed files
RUN mkdir -p /root/file
COPY * /root/file/

# install bases file
RUN yum -y update && yum install -y -q \
    build-essential \
    vim  \
    unzip  \
    net-tools  \
    git  \
    autoreconf  \
    initscripts \
    gcc \
    patch  \
    telnet  \
    gettext \
    libtool  \
    libevent \
    rsyslog  \
    wget     

# install autoconf
RUN mkdir /root/autoconf \
    && cd /root/autoconf \
    && wget --inet4-only  http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz  \
    && tar xzvf autoconf-2.69.tar.gz \
    && cd autoconf-2.69 \
    && ./configure  \
    && make  \
    && make  install \
    && rm -rf  /root/autoconf 


# install automake
RUN mkdir /root/automake \
    && cd /root/automake \
    && wget --inet4-only http://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz \
    && tar xzvf automake-1.15.tar.gz \
    && cd automake-1.15 \
    && ./configure  \
    && make  \
    && make  install \
    && rm -rf /root/automake 

# install netcat
RUN mkdir /root/netcat \
    && cd /root/netcat \
    && wget --inet4-only  https://downloads.sourceforge.net/project/netcat/netcat/0.7.1/netcat-0.7.1.tar.gz?r=http%3A%2F%2Fnetcat.sourceforge.net%2Fdownload.php -O netcat-0.7.1.tar.gz \
    && tar xzvf netcat-0.7.1.tar.gz \
    && cd /root/netcat/netcat-0.7.1 \
    && ./configure \
    && make  \
    && make  install \ 
    && rm -rf /root/netcat 

# install python 2.7
RUN mkdir /root/python \
    && cd /root/python \
    && wget --inet4-only https://www.python.org/ftp/python/2.7.14/Python-2.7.14.tgz \
    && tar zxf Python-2.7.14.tgz \
    && cd /root/python/Python-2.7.14 \
    && ./configure  \
    && make  \
    && make  install \
    && rm -rf /root/python \
    && echo "export PATH=/usr/local/bin:$PATH" >>  /etc/profile 
    
# install cryptlib
RUN mkdir /root/cryptlib \
    && cd /root/cryptlib \
#    && wget  --inet4-only --passive ftp://ftp.franken.de/pub/crypt/cryptlib/cl3431.zip \
    && cp /root/file/cl3431.zip /root/cryptlib/ \
    && unzip -a cl3431.zip -d cryptlib3431 \
    && cd cryptlib3431 \
    && make  shared  \
    && install -o root -g root -m 755 libcl.so.3.4.3 /usr/local/lib \
    && ln -s /usr/local/lib/libcl.so.3.4.3 /usr/local/lib/libcl.so.3.4  \
    && ln -s /usr/local/lib/libcl.so.3.4.3 /usr/local/lib/libcl.so  \
    && install -o root -g root -m 644 cryptlib.h /usr/local/include \
    && rm -rf /root/cryptlib 

# install openssl1.0.2l
RUN mkdir /root/openssl \
    && cd /root/openssl \
    && wget --inet4-only https://www.openssl.org/source/openssl-1.0.2l.tar.gz \
    && tar xzvf openssl-1.0.2l.tar.gz \
    && cd openssl-1.0.2l \
    && ./config  shared enable-rfc3779 \
    && make  depend \
    && make  \
    && make  install \
    && echo "export PATH=/usr/local/ssl/bin:$PATH" >> /etc/profile \
    && source /etc/profile \
    && rm -rf /root/openssl 


# install mysql
RUN mkdir /root/mysql \
    && cd /root/mysql \
    && rm -rf /var/lib/mysql  \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-server-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-client-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-devel-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-common-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-community-libs-5.7.20-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/Connector-ODBC/5.3/mysql-connector-odbc-5.3.9-1.el6.x86_64.rpm \
    && wget  --no-verbose --inet4-only https://dev.mysql.com/get/Downloads/Connector-ODBC/5.3/mysql-connector-odbc-setup-5.3.9-1.el6.x86_64.rpm \
    && yum  localinstall -y -q *.rpm  \ 
    && cp /root/file/mysqlinit.* /root/mysql/  \ 
#   && rm -rf /var/lib/mysql \ 
    && cp /etc/my.cnf /root/mysql/my.cnf \
    && echo 'skip-grant-tables' >> /etc/my.cnf \
    && service mysqld start \
    && cd /root/mysql \
    && chmod +x *.sh \
    && ./mysqlinit.sh \
    && cp /root/mysql/my.cnf  /etc/my.cnf \
    && rm -rf /root/mysql 

# install unixodbc
RUN mkdir /root/unixodbc \
    && cd /root/unixodbc \
    && wget --inet4-only ftp://ftp.unixodbc.org/pub/unixODBC/unixODBC-2.3.4.tar.gz \
    && tar xzvf unixODBC-2.3.4.tar.gz \
    && cd unixODBC-2.3.4 \
    && ./configure  \
    && make  \
    && make  install \ 
    && rm -rf /root/unixodbc \
    && mkdir -p /usr/local/etc/ \
    && cp /root/file/*.ini /usr/local/etc/  

# install crontab
RUN  mkdir /root/crontab \
    && cd /root/crontab \
    && wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/cronie-1.4.4-16.el6_8.2.x86_64.rpm \
    && wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/crontabs-1.10-33.el6.noarch.rpm \
    && wget http://www.rpmfind.net/linux/centos/6.10/os/x86_64/Packages/cronie-anacron-1.4.4-16.el6_8.2.x86_64.rpm \
    && rpm -ivh cronie-1.4.4-16.el6_8.2.x86_64.rpm --nodeps \
    && rpm -ivh crontabs-1.10-33.el6.noarch.rpm \
    && rpm -ivh cronie-anacron-1.4.4-16.el6_8.2.x86_64.rpm \
    && service crontab start \
    && rm -rf /root/crontab 
    
# install rpstir
RUN cp /root/file/rpstir.test.conf /root/.rpstir.test.conf \
    && mkdir -p /root/rpstir /usr/local/etc/rpstir /usr/local/var/cache/rpstir \
             /usr/local/var/lib/rpstir   /usr/local/var/log/rpstir \
    && cp /root/file/rpstir.conf /root/rpstir/  \
    && cd /root/rpstir \
    && git clone https://github.com/bgpsecurity/rpstir.git \
    && cd ./rpstir \
    && ./autogen.sh \
    && ./configure -q \
    && make  \
    && mkdir -p /usr/local/var/cache/rpstir-tmp \
##    && make -s check \ 
    && make install \
    && cp /root/rpstir/rpstir.conf /usr/local/etc/rpstir/rpstir.conf   \



# clean all rmp
    && yum clean all \
    && rm -rf /root/file 


# start 
#CMD /bin/bash
ENTRYPOINT service mysqld restart  && /bin/bash 


    


