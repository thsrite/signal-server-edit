//package org.whispersystems.textsecuregcm.tests.util;
//
//import com.amazonaws.HttpMethod;
//import io.minio.errors.MinioException;
//import org.junit.Test;
//import org.whispersystems.textsecuregcm.s3.UrlSigner;
//import org.xmlpull.v1.XmlPullParserException;
//
//import java.io.IOException;
//import java.net.URL;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//
//import static org.assertj.core.api.Assertions.assertThat;
//
//public class UrlSignerTest {
//
//  @Test
//  public void testTransferAcceleration() throws MinioException, XmlPullParserException, NoSuchAlgorithmException, InvalidKeyException, IOException {
////    UrlSigner signer = new UrlSigner("foo", "bar", "attachments-test");
////    URL url = signer.getPreSignedUrl(1234, HttpMethod.GET, false);
//
//    UrlSigner signer = new UrlSigner("foo", "bar", "attachments-test","");
//    String url = signer.getPreSignedUrl(1234, HttpMethod.GET);
////    assertThat(url).hasHost("attachments-test.s3-accelerate.amazonaws.com");
//    assertThat(url).hasHost("attachments-test.s3-accelerate.amazonaws.com");
//  }
//
//  @Test
//  public void testTransferUnaccelerated() throws MinioException, XmlPullParserException, NoSuchAlgorithmException, InvalidKeyException, IOException {
////    UrlSigner signer = new UrlSigner("foo", "bar", "attachments-test");
////    URL url = signer.getPreSignedUrl(1234, HttpMethod.GET, true);
//    UrlSigner signer = new UrlSigner("foo", "bar", "attachments-test","");
//    URL url = signer.getPreSignedUrl(1234, HttpMethod.GET);
//    assertThat(url).hasHost("s3.amazonaws.com");
////    assertThat(url).hasHost("s3.amazonaws.com");
//  }
//
//}
