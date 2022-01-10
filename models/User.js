const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1 //중복X
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0 //임의로 지정한하면 0
    },
    image: String,
    token: { //유효성? 유저성?
        type: String
    },
    tokenExp: { //토큰의 유효기간
        type:Number
    }
})

// register route에서 save(저장)하기 전에 무엇을 한다.
userSchema.pre('save', function(next){
    var user = this; // 위에 유저 틀을 가리킴

    if(user.isModified('password')) {
    // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err, hash) {
                // Store hash in your password DB.
                if(err) return next(err)
                user.password = hash
                next()
            })
        })
    } else { // 비밀번호를 바꾸는게 아니면 바로 나가는 것
        next()
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // palinPassword 1234567  암호화된 비밀번호 q349tqpe9gpwe0a0u어쩌구
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return cb(err) // 암호가 틀린경우 콜백 error 
        cb(null, isMatch) // 암호가 맞는 경우 에러가 없고 isMatch(맞다)

    })
}

userSchema.methods.generateToken = function(cb) {
    // jsonwebtoken을 이용해서 token을 생성하기
    var user = this;
    // console.log('user._id', user._id)
    var token = jwt.sign(user._id.toHexString(), 'secretToken')
    //user._id + 'secretToken' = token
    //->
    //'scretToken' -> user._id

    user.token = token // token을 user에 저장
    user.save(function(err, user) {
        if(err) return cb(err); // 에러일 때 콜백으로 에러를 전달
        cb(null, user) // 저장이 잘됐으면 오류가 없음
    })
}

userSchema.statics.findByToken = function(token, cb) {
    var user = this;
    
    //user._id + '' = token
    // 토큰을 디코드한다.
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // 유저 아이디를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인
        user.findOne({ "_id": decoded, "token":token}, function(err, user){
            if(err) return cb(err);
            cb(null, user)

        })
    })
}


const User = mongoose.model('User', userSchema) //스키마를 모델로 감싸줌
// 모델의 이름을 적어줌

module.exports = { User } // 이 모델을 다른 파일에서도 쓰고 싶으니까 모듈화