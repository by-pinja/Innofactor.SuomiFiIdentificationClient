﻿using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using Innofactor.SuomiFiIdentificationClient.Support;

namespace Innofactor.SuomiFiIdentificationClient.Saml {

  /// <summary>
  /// SAML HTTP Redirect binding
  /// </summary>
  public class Saml2HttpRedirect {

    private readonly RsaShaCrypto crypto;

    public Saml2HttpRedirect(string relayState, RsaShaCrypto crypto) {
      RelayState = relayState;
      this.crypto = crypto;
    }

    public string RedirectUrl { get; private set; }

    public string RelayState { get; }

    private string AddSignature(string queryString) {

      queryString += "&SigAlg=" + Uri.EscapeDataString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

      var signatureValue = GetSignature(Encoding.UTF8.GetBytes(queryString));

      queryString += "&Signature=" + Uri.EscapeDataString(Convert.ToBase64String(signatureValue));

      return queryString;

    }

    private byte[] GetSignature(byte[] contentBytes) {
      return crypto.SignData(contentBytes);
    }

    private string Serialize(string payload) {
      using var compressed = new MemoryStream();
      using (var writer = new StreamWriter(new DeflateStream(compressed, CompressionLevel.Optimal, true))) {
        writer.Write(payload);
      }

      var result = System.Net.WebUtility.UrlEncode(Convert.ToBase64String(compressed.ToArray()));

      return result;

    }

    public void Run(XElement xml) {

      var serializedRequest = Serialize(xml.ToString());

      var queryString = "SAMLRequest=" + serializedRequest
                        + (!string.IsNullOrEmpty(RelayState) ? "&RelayState=" + Uri.EscapeDataString(RelayState) : string.Empty);

      RedirectUrl = AddSignature(queryString);

    }

  }

}
