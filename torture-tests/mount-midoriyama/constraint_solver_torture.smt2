; Obstacle 6.5: Constraint solver torture (pathological SMT instance)
; Goal: enforce solver timeouts and graceful degradation instead of hangs.

(set-logic QF_AUFBV)
; External harness should still enforce its own timeout; this is advisory.
(set-option :timeout 3000)

; Pigeonhole-style distinctness on 4-bit space (17 pigeons, 16 holes).
(declare-fun x0 () (_ BitVec 4))
(declare-fun x1 () (_ BitVec 4))
(declare-fun x2 () (_ BitVec 4))
(declare-fun x3 () (_ BitVec 4))
(declare-fun x4 () (_ BitVec 4))
(declare-fun x5 () (_ BitVec 4))
(declare-fun x6 () (_ BitVec 4))
(declare-fun x7 () (_ BitVec 4))
(declare-fun x8 () (_ BitVec 4))
(declare-fun x9 () (_ BitVec 4))
(declare-fun x10 () (_ BitVec 4))
(declare-fun x11 () (_ BitVec 4))
(declare-fun x12 () (_ BitVec 4))
(declare-fun x13 () (_ BitVec 4))
(declare-fun x14 () (_ BitVec 4))
(declare-fun x15 () (_ BitVec 4))
(declare-fun x16 () (_ BitVec 4))

(assert (distinct x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16))

; Non-linear and mixed constraints to increase difficulty.
(assert (= (bvmul x0 x1) (bvadd x2 x3)))
(assert (= (bvxor x4 x5) (bvand x6 x7)))
(assert (= (bvadd x8 x9) (bvadd x10 x11)))
(assert (= (bvor (bvshl x12 #b0011) (bvlshr x13 #b0001)) (bvxor x14 x15)))
(assert (= x16 (bvnot (bvxor x0 x8))))

(check-sat)
(get-model)
