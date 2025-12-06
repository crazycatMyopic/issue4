package dev.alcazaar.chessfx.domain.remote.test;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.socket.IceTcpServerSocketWrapper;
import org.ice4j.socket.IceTcpSocketWrapper;
import org.ice4j.stack.StunClientTransaction;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;

import java.net.Socket;
import java.nio.charset.StandardCharsets;

import static dev.alcazaar.chessfx.domain.remote.Remote.nonce;
import static dev.alcazaar.chessfx.domain.remote.Remote.relam;

public class POL {

    // TURN server (TCP)
    private static final String TURN_HOST = "in.relay.metered.ca";
    private static final int TURN_PORT = 80;

    // credentials (use your own)
    private static final String USERNAME = "myusername";
    private static final String PASSWORD = "mypassword";

    public static void main(String[] args) throws Exception {

        // TCP socket directly to TURN
        Socket tcp = new Socket(TURN_HOST, TURN_PORT);
        tcp.setSoTimeout(5000);

        // Wrap TCP inside an ice4j TransportAddress
        TransportAddress local = new TransportAddress(
                tcp.getLocalAddress().getHostAddress(),
                tcp.getLocalPort(),
                Transport.TCP);

        TransportAddress server = new TransportAddress(
                TURN_HOST,
                TURN_PORT,
                Transport.TCP);

        // Create TURN stack
        StunStack stack = new StunStack();
        stack.addSocket(new IceTcpSocketWrapper(tcp),server);

        //------------------------------------------------------
        // 1. Send first ALLOCATE (unauthenticated)
        //------------------------------------------------------
        Request first = MessageFactory.createAllocateRequest();
        first.putAttribute(AttributeFactory.createRequestedTransportAttribute(RequestedTransportAttribute.UDP));
        first.putAttribute(AttributeFactory.createUsernameAttribute(USERNAME));
        first.putAttribute(AttributeFactory.createRealmAttribute(relam.getBytes(StandardCharsets.UTF_8)));
        first.putAttribute(AttributeFactory.createNonceAttribute(nonce.getBytes(StandardCharsets.UTF_8)));
//        first.putAttribute(AttributeFactory.createMessageIntegrityAttribute(USERNAME));
        TransactionID t1 =
                stack.sendRequest(first, server, local, new AbstractResponseCollector() {
                    @Override
                    protected void processFailure(BaseStunMessageEvent event) {
                        System.out.println("First ALLOCATE failed: " + event.getMessage());
                    }

                    @Override
                    public void processResponse(StunResponseEvent event) {
                        System.out.println("First ALLOCATE success: " + event.getMessage());

                    }
                });
        System.out.println("First ALLOCATE sent " + t1);
        Thread.sleep(10000);
//        Message resp1 = t1.waitForResponse();
//        if (resp1 == null)
//            throw new RuntimeException("No response for first ALLOCATE (TCP).");
//
//        ErrorCodeAttribute err = (ErrorCodeAttribute)
//                resp1.getAttribute(Attribute.ERROR_CODE);
//
//        if (err == null || err.getErrorCode() != 401)
//            throw new RuntimeException("Expected 401 Unauthorized challenge.");
//
//        RealmAttribute realmAttr =
//                (RealmAttribute) resp1.getAttribute(Attribute.REALM);
//        NonceAttribute nonceAttr =
//                (NonceAttribute) resp1.getAttribute(Attribute.NONCE);
//
//        String realm = realmAttr.getRealm();
//        String nonce = nonceAttr.getValue();
//
//        //------------------------------------------------------
//        // 2. Send authenticated ALLOCATE
//        //------------------------------------------------------
//        Request second = MessageFactory.createAllocateRequest();
//        second.addAttribute(new RequestedTransportAttribute(RequestedTransportAttribute.UDP));
//        second.addAttribute(AttributeFactory.createUsernameAttribute(USERNAME));
//        second.addAttribute(AttributeFactory.createRealmAttribute(realm));
//        second.addAttribute(AttributeFactory.createNonceAttribute(nonce));
//        second.addAttribute(new MessageIntegrityAttribute());
//
//        StunClientTransaction t2 =
//                stack.sendRequest(second, server, local, PASSWORD);
//
//        Message resp2 = t2.waitForResponse();
//        if (resp2 == null)
//            throw new RuntimeException("No response to authenticated ALLOCATE.");
//
//        if (!resp2.isSuccessResponse())
//            throw new RuntimeException("ALLOCATE failed: " + resp2);

        //------------------------------------------------------
        // 3. Extract XOR-RELAYED-ADDRESS
        //------------------------------------------------------
//        XorRelayedAddressAttribute relayed =
//                (XorRelayedAddressAttribute)
//                        resp2.getAttribute(Attribute.XOR_RELAYED_ADDRESS);
//
//        if (relayed == null)
//            throw new RuntimeException("No XOR-RELAYED-ADDRESS returned.");
//
//        System.out.println("Relay address: "
//                + relayed.getAddress().getHostAddress()
//                + ":" + relayed.getPort());

        tcp.close();
    }
}
