package main

import "testing"

// BenchmarkRatchet_EncryptDecrypt измеряет скорость одного раунда encrypt/decrypt
func BenchmarkRatchet_EncryptDecrypt(b *testing.B) {
	serverECDH, _    := generateDH()
	serverRatchet, _ := generateDH()
	clientECDH, _    := generateDH()

	clientShared, _ := dhCompute(clientECDH, serverECDH.PubHex)
	serverShared, _ := dhCompute(serverECDH, clientECDH.PubHex)
	SK1, _          := kdfSK(clientShared)
	SK2, _          := kdfSK(serverShared)

	serverSess := newRatchetSession()
	serverSess.InitBob(SK2, serverRatchet)

	aliceDH, _ := generateDH()
	dhOut, _   := dhCompute(aliceDH, serverRatchet.PubHex)
	rk, cks, _ := kdfRK(SK1, dhOut)
	clientSess := newRatchetSession()
	clientSess.RK = rk; clientSess.CKs = cks
	clientSess.DHs = aliceDH; clientSess.DHrHex = serverRatchet.PubHex

	payload := []byte(`{"action":"benchmark","data":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt, _ := clientSess.Encrypt(payload)
		serverSess.Decrypt(pkt)
		resp, _ := serverSess.Encrypt(payload)
		clientSess.Decrypt(resp)
	}
}
