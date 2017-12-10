(ns clj-jwt.format)

(defn- parameter-length [size]
  (+ (int (/ size 8))
     (if (== (mod size 8) 0)
       0 1)))

(defn- sequence-start [signature] 
  (if (== (get signature 1) 89)
    2 1))

(defn- sequence-length
  [signature]
  (get signature (sequence-start signature)))

(defn- r-length 
  [signature]
  (get signature (+ (sequence-start signature) 2)))

(defn- r-offset
  [signature]
  (+ (sequence-start signature) 3))

(defn- s-length
  [signature]
  (get signature
       (+ (r-offset signature)
          (r-length signature)
          1)))

(defn- s-offset
  [signature]
  (+ (r-offset signature)
     (r-length signature)
     2))

(defn- segment
  [signature max-length offset length]
  (let [padding (- max-length length)
        start (+ offset (max (* -1 padding) 0))
        end (+ offset length)]
    (->> signature
         (take end)
         (drop start))))

(defn- r
  [signature alg]
  (segment signature
           (parameter-length alg)
           (r-offset signature)
           (r-length signature)))

(defn- s
  [signature alg]
  (segment signature
           (parameter-length alg)
           (s-offset signature)
           (s-length signature)))

(defn der->jose
  [signature alg]
  (byte-array (concat (r signature alg) (s signature alg))))
