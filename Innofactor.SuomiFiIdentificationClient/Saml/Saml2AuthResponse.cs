using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Innofactor.SuomiFiIdentificationClient.Support;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Saml2;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;

namespace Innofactor.SuomiFiIdentificationClient.Saml {

  [Serializable]
  public class Saml2AuthResponse {

    private static readonly ILogger<Saml2AuthResponse> log = new LoggerFactory().CreateLogger<Saml2AuthResponse>();

    private static string DecodeBase64(string base64) {
      var data = Convert.FromBase64String(base64);
      var decoded = Encoding.UTF8.GetString(data);
      return decoded;
    }

    public static Saml2AuthResponse Create(string samlResponse,
      Saml2Id responseToId,
      EntityId issuer,
      X509Certificate2 idpCert,
      X509Certificate2 serviceCertificate,
      EntityId serviceId) {

      var decoded = DecodeBase64(samlResponse);
      var xmlDoc = new XmlDocument();
      xmlDoc.PreserveWhitespace = true;
      xmlDoc.LoadXml(decoded);

      var response = new Saml2Response(xmlDoc.DocumentElement, responseToId);

      if (response.Status != Saml2StatusCode.Success) {
        log.LogWarning("SAML authentication error: " + response.Status + " (" + response.StatusMessage + ")");
        return new Saml2AuthResponse(false) { Status = response.Status };
      }

      var spOptions = new SPOptions();
      spOptions.EntityId = serviceId;
      spOptions.ServiceCertificates.Add(serviceCertificate);
      var options = new Options(spOptions);
      var idp = new IdentityProvider(issuer, spOptions);
      idp.SigningKeys.AddConfiguredKey(idpCert);
      options.IdentityProviders.Add(idp);

      System.Security.Claims.ClaimsIdentity[] identities = null;
      try
      {
        identities = response.GetClaims(options)?.ToArray();
      }
      catch (Sustainsys.Saml2.Exceptions.Saml2ResponseFailedValidationException ex)
      {
        if (ex.Message.Contains("could not be decrypted") && decoded.Contains("http://www.w3.org/2009/xmlenc11#aes128-gcm"))
        {
          DecryptAesGcmHybrid(xmlDoc, serviceCertificate);
          return ParseResponseFromXml(xmlDoc);
        }
        else
        {
          throw;
        }
      }
      

      if (identities == null || identities.Length == 0)
        return new Saml2AuthResponse(false);

      var identity = identities.First();
      var firstName = identity.FindFirstValue(AttributeNames.GivenName) ?? identity.FindFirstValue(AttributeNames.EidasCurrentGivenName);
      var lastName = identity.FindFirstValue(AttributeNames.Sn);
      var ssn = identity.FindFirstValue(AttributeNames.NationalIdentificationNumber);
      var foreignPersonIdentifier = identity.FindFirstValue(AttributeNames.ForeignPersonIdentifier);
      var nameId = identity.FindFirstValue(AttributeNames.NameIdentifier);
      var sessionId = identity.FindFirstValue(AttributeNames.SessionIndex);

      return new Saml2AuthResponse(true) { FirstName = firstName, LastName = lastName, SSN = ssn, RelayState = response.RelayState, NameIdentifier = nameId, SessionIndex = sessionId, ForeignPersonIdentifier = foreignPersonIdentifier };

    }

    private static Saml2AuthResponse ParseResponseFromXml(XmlDocument xmlDoc)
    {
      var response = new Saml2AuthResponse(true);

      foreach(XmlElement c in xmlDoc.GetElementsByTagName("saml2:AttributeStatement")[0].ChildNodes)
      {
        switch (c.GetAttribute("Name"))
        {
          case AttributeNames.GivenName:
            response.FirstName = c.FirstChild.InnerText;
            break;
          case AttributeNames.EidasCurrentGivenName:
            response.FirstName = response.FirstName != null ? response.FirstName : c.FirstChild.InnerText;
            break;
          case AttributeNames.Sn:
            response.LastName = c.FirstChild.InnerText;
            break;
          case AttributeNames.NationalIdentificationNumber:
            response.SSN = c.FirstChild.InnerText;
            break;
          case AttributeNames.ForeignPersonIdentifier:
            response.ForeignPersonIdentifier = c.FirstChild.InnerText;
            break;
          case AttributeNames.NameIdentifier:
            response.NameIdentifier = c.FirstChild.InnerText;
            break;
          case AttributeNames.SessionIndex:
            response.SessionIndex = c.FirstChild.InnerText;
            break;
          default:
            break;
        }
      }

      response.NameIdentifier = (xmlDoc.GetElementsByTagName("saml2:NameID")[0]).FirstChild.InnerText;
      response.SessionIndex = (xmlDoc.GetElementsByTagName("saml2:AuthnStatement")[0]).Attributes.GetNamedItem("SessionIndex").InnerText;
      
      return response;
    }

    private static void DecryptAesGcmHybrid(XmlDocument xml, X509Certificate2 cert)
    {
      XmlElement encData = xml.GetElementsByTagName("xenc:EncryptedData")[0] as XmlElement;
      XmlElement keyInfo = encData.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "KeyInfo");
      XmlElement encryptedKey = keyInfo.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "EncryptedKey");
      XmlElement encKeyCipherData = encryptedKey.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "CipherData");
      XmlElement encKeyCipherValue = encKeyCipherData.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "CipherValue");
      XmlElement encDataCipherData = encData.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "CipherData");
      XmlElement encDataCipherValue = encDataCipherData.ChildNodes.Cast<XmlElement>().First(x => x.LocalName == "CipherValue");

      using (RSA rsa = cert.GetRSAPrivateKey())
      {
        var key = rsa.Decrypt(Convert.FromBase64String(encKeyCipherValue.InnerText), RSAEncryptionPadding.OaepSHA1);
        var fullCipher = Convert.FromBase64String(encDataCipherValue.InnerText);

        using (var aes = new AesGcm(key))
        {
          var nonce = new byte[12];
          var tag = new byte[16];
          var cipher = new byte[fullCipher.Length - nonce.Length - tag.Length];
          Buffer.BlockCopy(fullCipher, 0, nonce, 0, nonce.Length);
          Buffer.BlockCopy(fullCipher, fullCipher.Length - tag.Length, tag, 0, tag.Length);
          Buffer.BlockCopy(fullCipher, nonce.Length, cipher, 0, cipher.Length);

          var res = new byte[cipher.Length];
          aes.Decrypt(nonce, cipher, tag, res);

          XmlDocument decryptedAssertionNode = new XmlDocument();
          decryptedAssertionNode.LoadXml(Encoding.UTF8.GetString(res));
          XmlNode encryptedAssertionNode = xml.GetElementsByTagName("saml2:EncryptedAssertion")[0] as XmlNode;

          xml.LastChild.RemoveChild(encryptedAssertionNode);
          xml.LastChild.AppendChild(xml.ImportNode(decryptedAssertionNode.DocumentElement, true));
        }
      }
    }

    public Saml2AuthResponse() { }

    public Saml2AuthResponse(bool success) {
      Success = success;
    }

    public string FirstName { get; set; }

    public string LastName { get; set; }

    public string RelayState { get; set; }

    public string SSN { get; set; }
    public string ForeignPersonIdentifier { get; set; }
    /// <summary>
    /// Name / Session identifier used for Suomi.Fi logout request
    /// </summary>
    public string NameIdentifier { get; set; }
    /// <summary>
    /// Session identifier for Suomi.Fi logout request
    /// </summary>
    public string SessionIndex { get; set; }
    public Saml2StatusCode Status { get; set; }

    public bool Success { get; set; }

  }

}
