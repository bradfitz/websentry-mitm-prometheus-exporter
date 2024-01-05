deploy:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o websentry-mitm-prometheus-exporter.linux
	rsync -avPW websentry-mitm-prometheus-exporter.linux root@10.15.25.2:
