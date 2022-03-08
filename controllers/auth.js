const bcryptjs = require("bcryptjs");
const { response } = require("express");
const Usuario = require("../models/Usuario");
const { generarJWT } = require("../helpers/jwt");

const crearUsuario = async (req, res = response) => {
  const { email, password } = req.body;

  //   if (name.length < 5) {
  //     return res.status(400).json({
  //       ok: false,
  //       msg: "El nombre de ser de 5 letras o más",
  //     });
  //   }

  try {
    let usuario = await Usuario.findOne({ email });

    if (usuario) {
      return res.status(400).json({
        ok: false,
        msg: "Un usuario ya existe con ese correo",
      });
    }

    usuario = new Usuario(req.body);

    //Encriptar contraseña
    const salt = bcryptjs.genSaltSync();
    usuario.password = bcryptjs.hashSync(password, salt);

    await usuario.save();

    //Generar JWT

    const token = await generarJWT(usuario.id, usuario.name);

    res.status(201).json({
      ok: true,
      uid: usuario.id,
      name: usuario.name,
      token,
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      msg: "Por favor, hable con el administrador",
    });
  }
};

const loginUsuario = async (req, res = response) => {
  const { email, password } = req.body;

  try {
    const usuario = await Usuario.findOne({ email });

    if (!usuario) {
      return res.status(400).json({
        ok: false,
        msg: "Un usuario no existe con ese email",
      });
    }

    //Confirmar contraseñas
    const valPassword = bcryptjs.compareSync(password, usuario.password);

    if (!valPassword) {
      return res.status(400).json({
        ok: false,
        msg: "Password incorrecto",
      });
    }

    // Generar nuestro JWT
    const token = await generarJWT(usuario.id, usuario.name);

    res.status(201).json({
      ok: true,
      uid: usuario.id,
      name: usuario.name,
      token,
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      msg: "Por favor, hable con el administrador",
    });
  }
};

const revalidarToken = async(req, res = response) => {
  const { uid, name } = req;

  // Generar nuestro JWT
  const token = await generarJWT(uid, name);

  res.json({
    ok: true,
    token,
    uid,
    name
  });
};

module.exports = {
  crearUsuario,
  loginUsuario,
  revalidarToken,
};
