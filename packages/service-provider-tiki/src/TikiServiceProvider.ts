import {
  BNString,
  EncryptedMessage,
  getPubKeyECC,
  IServiceProvider,
  PubKeyType,
  ServiceProviderArgs,
  StringifiedType,
  toPrivKeyEC,
} from "@tkey/common-types";
import axios from "axios";
import BN from "bn.js";
import { curve } from "elliptic";

export interface ITikiServiceProvider extends IServiceProvider {
  hostUrl: string;
}

class TikiServiceProvider implements ITikiServiceProvider {
  enableLogging: boolean;

  // For easy serialization
  postboxKey: BN;

  serviceProviderName: string;

  hostUrl: string;

  constructor({ enableLogging = false, postboxKey = "", hostUrl = "http://localhost:9000/" }: ServiceProviderArgs & { hostUrl: string }) {
    this.enableLogging = enableLogging;
    this.postboxKey = new BN(postboxKey, "hex");
    this.serviceProviderName = "TikiServiceProvider";
    this.hostUrl = hostUrl.endsWith("/") ? hostUrl.substring(0, hostUrl.length - 1) : hostUrl;
  }

  static fromJSON(value: StringifiedType): IServiceProvider {
    const { enableLogging, postboxKey, serviceProviderName, hostUrl } = value;
    if (serviceProviderName !== "TikiServiceProvider") return undefined;

    return new TikiServiceProvider({ enableLogging, postboxKey, hostUrl });
  }

  async encrypt(msg: Buffer): Promise<EncryptedMessage> {
    const { data } = await axios.post(`${this.hostUrl}/encrypt`, {
      msg,
      postboxKey: this.postboxKey.toString("hex"),
    });
    return data;
  }

  async decrypt(msg: EncryptedMessage): Promise<Buffer> {
    const { data } = await axios.post(`${this.hostUrl}/decrypt`, {
      msg,
      postboxKey: this.postboxKey.toString("hex"),
    });
    return Buffer.from(data);
  }

  retrievePubKeyPoint(): curve.base.BasePoint {
    return toPrivKeyEC(this.postboxKey).getPublic();
  }

  retrievePubKey(type: PubKeyType): Buffer {
    if (type === "ecc") {
      return getPubKeyECC(this.postboxKey);
    }
    throw new Error("Unsupported pub key type");
  }

  sign(msg: BNString): string {
    const tmp = new BN(msg, "hex");
    const sig = toPrivKeyEC(this.postboxKey).sign(tmp.toString("hex"));
    return Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN(0).toString(16, 2), "hex").toString("base64");
  }

  toJSON(): StringifiedType {
    return {
      enableLogging: this.enableLogging,
      postboxKey: this.postboxKey.toString("hex"),
      serviceProviderName: this.serviceProviderName,
    };
  }
}

export default TikiServiceProvider;
