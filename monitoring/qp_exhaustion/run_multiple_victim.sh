
for i in {8000..8019}
do
	./victim -a 10.0.8.1 -p $i &
	echo "victim with port $i started"
done
