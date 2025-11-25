import ssl
import socket

host = input("Please give you're domain target:  ") #create the target host/ domain pr IP you're going to resolve later
port = 433 #TCP HTTPS port

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #normal socket connection

context = ssl.create_default_context() #default ssl

secured_sock = context.wrap_socket(connection, server_hostname=host) #wrap the socket
secured_sock.connect((socket.gethostbyname(host), port))
domain = secured_sock.getpeercert()
print(domain)
