const Joi = require("joi");
const userValidation = (req, res, next) => {
  const { email, password } = req.body;
  const userInfo = { email, password };

  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } })
      .required(),

    password: Joi.string().min(3).max(30).required(),
  });
  const { error } = schema.validate(userInfo);
  if (error) {
    return res.status(501).json({ error: error.details[0].message });
  }
  next();
};

module.exports = { userValidation };
