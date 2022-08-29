const UserModel = require('../models/user-model')
const bcrypt = require('bcrypt')
const uuid = require('uuid')
const mailService = require('./mail-service')
const tokensService = require('../service/token-service')
const UserDto = require('../dtos/user-dto')
const ApiError = require('../exceptions/api-error')

class UserService {
    async registration(email, password) {
        const candidate = await UserModel.findOne({email})
        if (candidate) {
            throw new ApiError.BadRequest(`User ${email} already exist`)
        }
        const hashPassword = await bcrypt.hash(password, 3)
        const activationLink = uuid.v4()

        const user = await UserModel.create({email, password: hashPassword, activationLink})
        await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`)

        const userDto = new UserDto(user)
        const tokens = tokensService.generateTokens({...userDto})
        await tokensService.saveToken(userDto.id, tokens.refreshToken)

        return {
            ...tokens,
            user: userDto
        }
    }

    async activate(activateLink) {
        const user = await UserModel.findOne({activationLink})
        if (!user) {
            throw new ApiError.BadRequest('Wrong link')
        }
        user.isActivated = true
        await user.save()
    }
}

module.exports = new UserService()