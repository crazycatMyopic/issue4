package dev.alcazaar.chessfx.domain.remote.test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import static dev.alcazaar.chessfx.domain.remote.Remote.nonce;

public class TEST {

    private static final int STUN_HEADER = 20;
    private static final int MAGIC_COOKIE = 0x2112A442;

    public static void main(String[] args) throws Exception {

        String turnHost = "in.relay.metered.ca";
        int turnPort = 80;

        String username = "myusername";
        String password = "mypassword";
        String realm = "in.relay.metered.ca";

        Socket socket = new Socket(turnHost, turnPort);
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        
        byte[] transactionID2 = randomTransID();

        byte[] secondAllocate = buildSecondAllocate(
                transactionID2,
                username,
                realm,
                nonce,
                password
        );

        out.write(secondAllocate);
        out.flush();
        byte[] response2 = readStunMessage(in);

        byte[] relay = extractRelayAddress(response2, transactionID2);

        System.out.println("TURN Relay Address: " + relay[0] + "." + relay[1] + "." + relay[2] + "." + relay[3]);
        System.out.println("TURN Relay Port   : " + (((relay[4] & 0xFF) << 8) | (relay[5] & 0xFF)));

        socket.close();
    }
    
    private static byte[] buildSecondAllocate(
            byte[] tid,
            String username,
            String realm,
            String nonce,
            String password
    ) throws Exception {

        byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] realmBytes = realm.getBytes(StandardCharsets.UTF_8);
        byte[] nonceBytes = nonce.getBytes(StandardCharsets.UTF_8);

        byte[] a1key = (username + ":" + realm + ":" + password).getBytes(StandardCharsets.UTF_8);

        byte[] attrRequestedTransport = new byte[]{
                0x00, 0x19, 0x00, 0x04,
                0x11, 0x00, 0x00, 0x00
        };

        byte[] attrUsername = stunAttr(0x0006, usernameBytes);
        byte[] attrRealm = stunAttr(0x0014, realmBytes);
        byte[] attrNonce = stunAttr(0x0015, nonceBytes);

        // Temporary buffer WITHOUT integrity
        ByteBuffer tmp = ByteBuffer.allocate(2000);
        tmp.putShort((short) 0x0003); // Allocate
        tmp.putShort((short) 0); // Placeholder length
        tmp.putInt(MAGIC_COOKIE);
        tmp.put(tid);
        tmp.put(attrRequestedTransport);
        tmp.put(attrUsername);
        tmp.put(attrRealm);
        tmp.put(attrNonce);

        int lenBeforeMI = tmp.position();

        // Now compute MESSAGE-INTEGRITY over header+attributes so far
        byte[] messageSoFar = Arrays.copyOf(tmp.array(), tmp.position());
        int stunBodyLength = lenBeforeMI - STUN_HEADER;

        // Patch correct length BEFORE HMAC
        messageSoFar[2] = (byte) ((stunBodyLength >>> 8) & 0xFF);
        messageSoFar[3] = (byte) (stunBodyLength & 0xFF);

        byte[] hmac = hmacSha1(a1key, messageSoFar, 0, lenBeforeMI);

        byte[] attrMI = stunAttr(0x0008, hmac);

        // Now rebuild final message with correct total length
        int finalLength = lenBeforeMI - STUN_HEADER + attrMI.length;
        ByteBuffer finalBuf = ByteBuffer.allocate(STUN_HEADER + finalLength);
        finalBuf.putShort((short) 0x0003);
        finalBuf.putShort((short) finalLength);
        finalBuf.putInt(MAGIC_COOKIE);
        finalBuf.put(tid);
        finalBuf.put(attrRequestedTransport);
        finalBuf.put(attrUsername);
        finalBuf.put(attrRealm);
        finalBuf.put(attrNonce);
        finalBuf.put(attrMI);

        return finalBuf.array();
    }

    private static byte[] stunAttr(int type, byte[] data) {
        int padded = (data.length + 3) & ~3;
        ByteBuffer buf = ByteBuffer.allocate(4 + padded);
        buf.putShort((short) type);
        buf.putShort((short) data.length);
        buf.put(data);
        while (buf.position() % 4 != 0) buf.put((byte) 0);
        return buf.array();
    }
    
    private static byte[] extractRelayAddress(byte[] msg, byte[] tid) {
        System.out.println("message " + new String(msg));
        int idx = STUN_HEADER;
        System.out.println(msg.length);
        System.out.println("---------------");
        while (idx < msg.length) {
            int type = ((msg[idx] & 0xFF) << 8) | (msg[idx + 1] & 0xFF);
            int len = ((msg[idx + 2] & 0xFF) << 8) | (msg[idx + 3] & 0xFF);
            idx += 4;
            System.out.println(type);
            System.out.println(len);

            if (type == 32802) { // XOR-RELAYED-ADDRESS
                int family = msg[idx + 1] & 0xFF;
                int port = ((msg[idx + 2] & 0xFF) << 8) | (msg[idx + 3] & 0xFF);

                port ^= (MAGIC_COOKIE >>> 16);

                byte[] ip = Arrays.copyOfRange(msg, idx + 4, idx + 8);

                ByteBuffer cookie = ByteBuffer.allocate(4);
                cookie.putInt(MAGIC_COOKIE);

                for (int i = 0; i < 4; i++) {
                    ip[i] ^= cookie.array()[i];
                }

                return new byte[]{
                        ip[0], ip[1], ip[2], ip[3],
                        (byte) ((port >>> 8) & 0xFF),
                        (byte) (port & 0xFF)
                };
            }

            idx += ((len + 3) & ~3);
        }
        return new byte[0];
    }
    
    private static byte[] randomTransID() {
        byte[] tid = new byte[12];
        new Random().nextBytes(tid);
        return tid;
    }

    private static byte[] readStunMessage(InputStream in) throws Exception {
        byte[] hdr = in.readNBytes(20);
        int len = ((hdr[2] & 0xFF) << 8) | (hdr[3] & 0xFF);
        byte[] rest = in.readNBytes(len);
        return ByteBuffer.allocate(20 + len).put(hdr).put(rest).array();
    }

    private static byte[] hmacSha1(byte[] key, byte[] msg, int off, int len) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        return mac.doFinal(msg);
    }
}
