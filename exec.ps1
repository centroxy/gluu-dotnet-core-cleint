docker build -t projectname .
docker run -it -p 3000:3000 -e "ASPNETCORE_URLS=http://*:3000" projectname
