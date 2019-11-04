import forge from 'node-forge';
import SignPdfError from './SignPdfError';
import {removeTrailingNewLine} from './helpers';
const graphene = require('graphene-pk11');

export {default as SignPdfError} from './SignPdfError';

export const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';

export class SignPdf {
    constructor() {
        this.byteRangePlaceholder = DEFAULT_BYTE_RANGE_PLACEHOLDER;
        this.lastSignature = null;
    }


    signPkcs11(pdfBuffer) {
        function _encodePkcs1_v1_5(m, key, bt) {
            var eb = forge.util.createBuffer();

            // get the length of the modulus in bytes
            //var k = Math.ceil(key.n.bitLength() / 8);
            var k = Math.ceil(1024 / 8);

            /* use PKCS#1 v1.5 padding */
            if (m.length > (k - 11)) {
                var error = new Error('Message is too long for PKCS#1 v1.5 padding.');
                error.length = m.length;
                error.max = k - 11;
                throw error;
            }

            /* A block type BT, a padding string PS, and the data D shall be
              formatted into an octet string EB, the encryption block:
          
              EB = 00 || BT || PS || 00 || D
          
              The block type BT shall be a single octet indicating the structure of
              the encryption block. For this version of the document it shall have
              value 00, 01, or 02. For a private-key operation, the block type
              shall be 00 or 01. For a public-key operation, it shall be 02.
          
              The padding string PS shall consist of k-3-||D|| octets. For block
              type 00, the octets shall have value 00; for block type 01, they
              shall have value FF; and for block type 02, they shall be
              pseudorandomly generated and nonzero. This makes the length of the
              encryption block EB equal to k. */

            // build the encryption block
            eb.putByte(0x00);
            eb.putByte(bt);

            // create the padding
            var padNum = k - 3 - m.length;
            var padByte;
            // private key op
            if (bt === 0x00 || bt === 0x01) {
                padByte = (bt === 0x00) ? 0x00 : 0xFF;
                for (var i = 0; i < padNum; ++i) {
                    eb.putByte(padByte);
                }
            } else {
                // public key op
                // pad with random non-zero values
                while (padNum > 0) {
                    var numZeros = 0;
                    var padBytes = forge.random.getBytes(padNum);
                    for (var i = 0; i < padNum; ++i) {
                        padByte = padBytes.charCodeAt(i);
                        if (padByte === 0) {
                            ++numZeros;
                        } else {
                            eb.putByte(padByte);
                        }
                    }
                    padNum = numZeros;
                }
            }

            // zero followed by message
            eb.putByte(0x00);
            eb.putBytes(m);

            return eb;
        }
        var emsaPkcs1v15encode = function (md, signature) {
            // get the oid for the algorithm
            var oid;
            if (md.algorithm in forge.pki.oids) {
                oid = forge.pki.oids[md.algorithm];
            } else {
                var error = new Error('Unknown message digest algorithm.');
                error.algorithm = md.algorithm;
                throw error;
            }
            var oidBytes = forge.asn1.oidToDer(oid).getBytes();

            // create the digest info
            var digestInfo = forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []);
            var digestAlgorithm = forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []);
            digestAlgorithm.value.push(forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, oidBytes));
            digestAlgorithm.value.push(forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''));
            var digest = forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING,
                false, md.digest().getBytes());
            // var digest = forge.asn1.create(
            //     forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING,
            //     false, signature);
            digestInfo.value.push(digestAlgorithm);
            digestInfo.value.push(digest);


            // encode digest info
            return forge.asn1.toDer(digestInfo).getBytes();
        };




        if (!(pdfBuffer instanceof Buffer)) {
            throw new SignPdfError(
                'PDF expected as Buffer.',
                SignPdfError.TYPE_INPUT,
            );
        }

        let { pdf, placeholderLength, byteRange } = this.getSignablePdfBuffer(pdfBuffer);

        let Module = graphene.Module;
        let module = Module.load('/lib64/libASEP11.so', "TEST TOKEN");

        module.initialize();
        let session = module.getSlots(0).open();
        session.login('1234');

        let signer = {}
        signer.sign = (buffer, algo) => {
            // let encoded = emsaPkcs1v15encode(buffer);

            console.log("ALGORITHM " + buffer.algorithm);
            let buf = session.find({ class: graphene.ObjectClass.PRIVATE_KEY }).items_[1]
            let key = session.getObject(buf);
            let sign = session.createSign("SHA1_RSA_PKCS", key);
            // let s = sign.once(buffer.digest().getBytes());
            
            // var content = forge.util.createBuffer(pdf.toString('binary'));

            // let contents = forge.util.createBuffer(pdf.toString('binary'));
            // console.log("contents: " +forge.util.encode64(contents.getBytes()));
            // let input = buffer.getRawInput();
            // var finalBlock = forge.util.createBuffer();
            // finalBlock.putBytes(input.bytes());
            // let s = sign.once(contents.getBytes());
            sign.update(pdf);
            //sign.update(buffer.getBytes());
            var tt = sign.final();
            // let s = sign.once();
            console.log("before return: " +tt.toString('base64'));
            return tt.toString('binary');
            // let s = sign.once(content.getBytes());
            
            // let encoded = emsaPkcs1v15encode(buffer, s.toString('binary'));
            // return encoded;
            // let s = sign.once(encoded);

            // let s = sign.once(_encodePkcs1_v1_5(encoded, {}, 0x01));
            return s;
            // return s.toString('binary');
            // let s = sign.once(encoded);
            // let hexs = s.toString('hex');
            // var ed = forge.util.createBuffer();
            // var zeros = Math.ceil(1024/8) - Math.ceil(hexs.length / 2);
            // while(zeros > 0) {
            //     ed.putByte(0x00);
            //     --zeros;
            // }
            // ed.putBytes(forge.util.hexToBytes(hexs));
            // return ed.getBytes();
            // return s;
            //return sign.final().toString('binary');
        };

        let buf = session.find({ class: graphene.ObjectClass.PRIVATE_KEY }).items_[1]
        let key = session.getObject(buf);
        let certificate = this.getCertFromSession(session, key.id.toString("hex"));
        let p7 = this.createPkcs7Message(pdf, certificate, signer);

        let enc = forge.util.encode64(forge.asn1.toDer(p7.toAsn1()).getBytes());
        console.log(enc);

        //console.log("Signature RSA-SHA1:", signature.toString("hex"));

        session.logout();
        module.finalize();

        // Check if the PDF has a good enough placeholder to fit the signature.
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();

        // placeholderLength represents the length of the HEXified symbols but we're
        // checking the actual lengths.
        if ((raw.length * 2) > placeholderLength) {
            throw new SignPdfError(
                `Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`,
                SignPdfError.TYPE_INPUT,
            );
        }

        // let signature = signatureBuf.toString('hex');
        let signature = Buffer.from(raw, 'binary').toString('hex');
        // Store the HEXified signature. At least useful in tests.
        this.lastSignature = signature;

        // Pad the signature with zeroes so the it is the same length as the placeholder
        signature += Buffer
            .from(String.fromCharCode(0).repeat((placeholderLength / 2) - raw.length))
            .toString('hex');

        //console.log(signature.length);
        //console.log(signature);

        // Place it in the document.
        pdf = Buffer.concat([
            pdf.slice(0, byteRange[1]),
            Buffer.from(`<${signature}>`),
            pdf.slice(byteRange[1]),
        ]);


        // Magic. Done.
        return pdf;
    }

    getCertFromSession(session, pkeyId) {
        let certs = session.find({class: graphene.ObjectClass.CERTIFICATE}).items_;
        for (let i=0; i < certs.length; i++) {
            let cert = session.getObject(certs[i]);
            //console.log(cert.id.toString());
            if (pkeyId == cert.id.toString("hex")) {
                //console.log("Found " + pkeyId);
                //console.log(cert.label.toString());
                let decoded = forge.asn1.fromDer(cert.value.toString('binary'));
                let c = forge.pki.certificateFromAsn1(decoded);

                return c;
            }
        }
    }

    sign(
        pdfBuffer,
        p12Buffer,
        additionalOptions = {},
    ) {
        const options = {
            asn1StrictParsing: false,
            passphrase: '',
            ...additionalOptions,
        };

        if (!(pdfBuffer instanceof Buffer)) {
            throw new SignPdfError(
                'PDF expected as Buffer.',
                SignPdfError.TYPE_INPUT,
            );
        }
        if (!(p12Buffer instanceof Buffer)) {
            throw new SignPdfError(
                'p12 certificate expected as Buffer.',
                SignPdfError.TYPE_INPUT,
            );
        }

        let { pdf, placeholderLength, byteRange } = this.getSignablePdfBuffer(pdfBuffer);

        // Convert Buffer P12 to a forge implementation.
        const forgeCert = forge.util.createBuffer(p12Buffer.toString('binary'));
        const p12Asn1 = forge.asn1.fromDer(forgeCert);
        const p12 = forge.pkcs12.pkcs12FromAsn1(
            p12Asn1,
            options.asn1StrictParsing,
            options.passphrase,
        );

        // Extract safe bags by type.
        // We will need all the certificates and the private key.
        const certBags = p12.getBags({
            bagType: forge.pki.oids.certBag,
        })[forge.pki.oids.certBag];
        const keyBags = p12.getBags({
            bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
        })[forge.pki.oids.pkcs8ShroudedKeyBag];

        const privateKey = keyBags[0].key;
        // Then add all the certificates (-cacerts & -clcerts)
        // Keep track of the last found client certificate.
        // This will be the public key that will be bundled in the signature.
        let certificate;
        Object.keys(certBags).forEach((i) => {
            const {publicKey} = certBags[i].cert;

            //p7.addCertificate(certBags[i].cert);

            // Try to find the certificate that matches the private key.
            if (privateKey.n.compareTo(publicKey.n) === 0
                && privateKey.e.compareTo(publicKey.e) === 0
            ) {
                certificate = certBags[i].cert;
            }
        });
        let p7 = this.createPkcs7Message(pdf, certificate, privateKey);

        /********
        // Here comes the actual PKCS#7 signing.
        const p7 = forge.pkcs7.createSignedData();
        // Start off by setting the content.
        p7.content = forge.util.createBuffer(pdf.toString('binary'));


        if (typeof certificate === 'undefined') {
            throw new SignPdfError(
                'Failed to find a certificate that matches the private key.',
                SignPdfError.TYPE_INPUT,
            );
        }

        // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
        p7.addSigner({
            key: privateKey,
            certificate,
            digestAlgorithm: forge.pki.oids.sha256,
            authenticatedAttributes: [
                {
                    type: forge.pki.oids.contentType,
                    value: forge.pki.oids.data,
                }, {
                    type: forge.pki.oids.messageDigest,
                    // value will be auto-populated at signing time
                }, 
                // {
                //     type: forge.pki.oids.signingTime,
                //     // value can also be auto-populated at signing time
                //     // We may also support passing this as an option to sign().
                //     // Would be useful to match the creation time of the document for example.
                //     value: new Date(),
                // },
            ],
        });

        // Sign in detached mode.
        p7.sign({detached: true});
        */

        let enc = forge.util.encode64(forge.asn1.toDer(p7.toAsn1()).getBytes());
        // console.log(enc);
        //console.log(p7.toAsn1());
        // Check if the PDF has a good enough placeholder to fit the signature.
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        // placeholderLength represents the length of the HEXified symbols but we're
        // checking the actual lengths.
        if ((raw.length * 2) > placeholderLength) {
            throw new SignPdfError(
                `Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`,
                SignPdfError.TYPE_INPUT,
            );
        }

        let signature = Buffer.from(raw, 'binary').toString('hex');
        // Store the HEXified signature. At least useful in tests.
        this.lastSignature = signature;

        // Pad the signature with zeroes so the it is the same length as the placeholder
        signature += Buffer
            .from(String.fromCharCode(0).repeat((placeholderLength / 2) - raw.length))
            .toString('hex');

        //console.log(signature.length);
        //console.log(signature);
        // Place it in the document.
        pdf = Buffer.concat([
            pdf.slice(0, byteRange[1]),
            Buffer.from(`<${signature}>`),
            pdf.slice(byteRange[1]),
        ]);

        // Magic. Done.
        return pdf;
    }

    createPkcs7Message(pdf, certificate, signer) {
        const p7 = forge.pkcs7.createSignedData();
        // Start off by setting the content.
        p7.content = forge.util.createBuffer(pdf.toString('binary'));


        p7.addCertificate(certificate);

        if (typeof certificate === 'undefined') {
            throw new SignPdfError(
                'Failed to find a certificate that matches the private key.',
                SignPdfError.TYPE_INPUT,
            );
        }

        // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
        p7.addSigner({
            key: signer,
            certificate,
            // digestAlgorithm: forge.pki.oids.sha256,
            digestAlgorithm: forge.pki.oids.sha1,
            // authenticatedAttributes: [
            //     {
            //         type: forge.pki.oids.contentType,
            //         value: forge.pki.oids.data,
            //     }, {
            //         type: forge.pki.oids.messageDigest,
            //         // value will be auto-populated at signing time
            //     }, 
            //     // {
            //     //     type: forge.pki.oids.signingTime,
            //     //     // value can also be auto-populated at signing time
            //     //     // We may also support passing this as an option to sign().
            //     //     // Would be useful to match the creation time of the document for example.
            //     //     value: new Date(),
            //     // },
            // ],
        });

        // Sign in detached mode.
        p7.sign({detached: true});

        return p7;
    }

    getSignablePdfBuffer(pdfBuffer) {
        let pdf = removeTrailingNewLine(pdfBuffer);

        // Find the ByteRange placeholder.
        const byteRangePlaceholder = [
            0,
            `/${this.byteRangePlaceholder}`,
            `/${this.byteRangePlaceholder}`,
            `/${this.byteRangePlaceholder}`,
        ];
        const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
        const byteRangePos = pdf.indexOf(byteRangeString);
        if (byteRangePos === -1) {
            throw new SignPdfError(
                `Could not find ByteRange placeholder: ${byteRangeString}`,
                SignPdfError.TYPE_PARSE,
            );
        }

        // Calculate the actual ByteRange that needs to replace the placeholder.
        const byteRangeEnd = byteRangePos + byteRangeString.length;
        const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
        const placeholderPos = pdf.indexOf('<', contentsTagPos);
        const placeholderEnd = pdf.indexOf('>', placeholderPos);
        const placeholderLengthWithBrackets = (placeholderEnd + 1) - placeholderPos;
        const placeholderLength = placeholderLengthWithBrackets - 2;
        const byteRange = [0, 0, 0, 0];
        byteRange[1] = placeholderPos;
        byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
        byteRange[3] = pdf.length - byteRange[2];
        let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
        actualByteRange += ' '.repeat(byteRangeString.length - actualByteRange.length);

        // Replace the /ByteRange placeholder with the actual ByteRange
        pdf = Buffer.concat([
            pdf.slice(0, byteRangePos),
            Buffer.from(actualByteRange),
            pdf.slice(byteRangeEnd),
        ]);

        // Remove the placeholder signature
        pdf = Buffer.concat([
            pdf.slice(0, byteRange[1]),
            pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
        ]);

        return { pdf, placeholderLength, byteRange };
    }
}

export default new SignPdf();
