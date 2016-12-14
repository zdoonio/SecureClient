
package com.clients;

/**
 * This represents the Client that can write and receive messages and ivs, 
 * as well as can encrypt and decrypt messages (always in CBC mode).
 * @author Karol
 */
public interface ChatClient extends DecEncClient, WriteReceiveClient {
    // nic tu nie ma, bo wszystko już odziedziczone po wyższych interfejsach.
}
