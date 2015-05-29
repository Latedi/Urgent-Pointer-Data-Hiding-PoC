# Urgent Pointer Data Hiding PoC
Proof of Concept for hiding data in the TCP protocol Urgent Pointer

This code utilizes raw sockets in linux to transfer data using the urgent pointer field.
Every packet has the same message set in the TCP data section and 2 bytes of the sercret message is put into the urgent pointer.
Therefore it might take some packets to complete the transfer. Note that this is only a proof of concept and many things could
be improved such as having a standard TCP handshake, terminating the connection correctly, alternating the decoy data to make
it seem more realistic, not sending data only through localhost, making sure that the data comes from the same IP and so on.

In practice a firewall could filter out the packets for being damaged (the urgent flag is not set) or zero the urgent pointer
field. An IDS would most certainly detect this as an anomaly and network sniffers as well. A more sophisticated scheme would
be more effective, and other fields in the headers could also be used.
