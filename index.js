const express = require('express')
const app = express()
const port = 3000
const bodyParser = require('body-parser');
const { auth } = require("./middleware/auth"); // 임포트하는것
const { User } = require("./models/User"); // User 틀만들어둔 것을 불러온다.
const cookieParser = require('cookie-parser');
const config = require('./config/key');
// ↓ bodyparser가 클라이언트에서 오는 정보를 서버에서 분석해서 가져올 수 있도록
// application/x-www-form-urlencoded이렇게 된 데이터를 분석해서 가져올 수 있게 해주는 것
app.use(bodyParser.urlencoded({extended: true}));
// application/json 타입으로 된것을 분석해서 가져올 수 있도록 하는 것
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require('mongoose')


mongoose.connect(config.mongoURI).then(() => console.log('MongoDB Connect...')).catch(err => console.log(err))


app.get('/', (req, res) => res.send('Hello World!'))

app.post('/api/users/register', (req, res) => { // 회원가입을 위한 register route만들기
    // 회원 가입 할 때 필요한 정보들을 client에서 가져오면
    // 그것들을 데이터 베이스에 넣어준다.

    const user = new User(req.body)

    // save -> 몽고디비에서 있는 메소드 // 유저모델에 저장해라
    // next()호출시 오게되는 곳
    user.save((err, userInfo) => {
        if (err) return res.json({ success: false, err }) // 에러가 생기면 에러메세지를 표시해라
        return res.status(200).json({
            success: true
        })
    }); // 회원가입을 위한 작업은 완료

    // req.body에 들어있을 수 있게 해주는 것이
    // body-parser가 있어서 그런 것.
    // body-parser를 이용해서 req.body로
    // 클라이언트에 보내는 정보를 받아준다.
});

app.post('/api/users/login', (req, res) => {
    // 요청된 이메일을 데이터베이스에서 있는지 찾는다.
    User.findOne({email: req.body.email }, (err, user) => {
        if(!user) {
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }
        // 요청된 이메일이 데이터베이스에 있다면 비밀번호가 맞는 비밀번호인지 확인
        user.comparePassword(req.body.password, (err, isMatch) => {
            if(!isMatch)
                return res.json({loginSuccess: false, message: "비밀번호가 틀렸습니다."})
            
            // 비밀번호 까지 맞다면 토큰을 생성하기.
            user.generateToken((err, user) => {
                if (err) return res.status(400).send(err); // 에러가 있는 경우에 에러를 전송.

                // 토큰을 저장한다. 어디에? 쿠키, 로컬스토리지 등등
                res.cookie("x_auth", user.token)
                    .status(200) // 성공했다는 표시
                    .json({loginSuccess: true, userId: user._id})
            })
        })
    })
})

// role이 0이면 일반유저, role이 0이 아니면 관리자 -> 개발자 맘대로 바꿀 수 있음.
app.get('/api/users/auth', auth, (req, res) => {
    // 여기까지 미들웨어를 통과해 왔다는 얘기는 Authentication이 True라는 말.
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
}) 


app.get('/api/users/logout', auth, (req, res) => {
    User.findOneAndUpdate({_id: req.user._id},
        {token: ""},
        (err, user) => {
            if (err) return res.json({success:false, err});
            return res.status(200).send({
                success: true
            })
        })

})

app.listen(port, () => console.log('Example app listening on port ${port}!'))