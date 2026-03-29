import re

with open('src/server_core.c', 'r') as f:
    text = f.read()

text = text.replace('if (!db_init(srv)) { fprintf(stderr, "[init] DB failed\\n"); return -1; }', 'if (init_logger() < 0) { fprintf(stderr, "[init] DB failed\\n"); return -1; }')
text = text.replace('db_close(srv);', 'close_logger();')

with open('src/server_core.c', 'w') as f:
    f.write(text)

with open('src/client_handler.c', 'r') as f:
    text = f.read()
    
text = re.sub(r'db_log_event\([^;]+;', '', text)
text = text.replace('c->session_id = db_open_session(srv, c->ip, c->port);', 'log_session_start(c->ip, c->socket_fd);')
text = text.replace('db_close_session(srv, c->session_id, c->frames_sent, c->bytes_sent);', 'log_session_end(c->socket_fd, c->bytes_sent);')

with open('src/client_handler.c', 'w') as f:
    f.write(text)
