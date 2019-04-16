pid=`ps -ef|grep 'rpki-transfer'|grep -v grep|awk '{print $2}'`
echo "The current process id is $pid"
if [ "$pid" = "" ]; then
    echo "pid is null"
else
    kill -9 $pid
    echo "shutdown success"
fi

