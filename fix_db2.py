with open('src/client_handler.c', 'r') as f:
    text = f.read()

text = text.replace('c->socket_fd', 'c->fd')

with open('src/client_handler.c', 'w') as f:
    f.write(text)
