# Priv_DB (Privilege Database)
Priv_DB is a Python sqlite3 Database System to store privileges of users in a sqlite3 Database.
There a - different privilege levels:
|     Name |                                        Privileges |                                     Notes |
|----------|---------------------------------------------------|-------------------------------------------|
|  Blocked |                          Blocked from the Service |                            A blocked User |
|   Common |                                 Common Privileges |       Everybody gets this privilege level |
|      VIP |               Common + new Features (for payment) |                  For Everyone whos paying |
| Verified |                                     Verified User |                           Verified People |
|     FR1P |                             All features for free |          For Friends or well known People |
|     Beta |                                        Beta stuff |                   Beta Tester / Developer |
|   Logger |                 Acces to realtime logs (log page) |       For Developer and authorized People |
|    Admin | Acces to the Admin page (block, delete ... users) | For the Admins and high authorized People |


User levels are stored in the Database levels which are higher than Common are verified with a token (generatet with the Servers private rsa key).
Loggers and Admins can also directly use tokens to acces the log or admin page. 
Direct tokens are also generated with the private rsa key and have a time expiration.
