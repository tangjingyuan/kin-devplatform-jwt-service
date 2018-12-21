import * as moment from "moment";
import { readFileSync } from "fs";
import * as jsonwebtoken from "jsonwebtoken";
import * as axios from "axios";
import { Request, Response, RequestHandler } from "express";

import { getDefaultLogger } from "./logging";
import { randomItem, path } from "./utils";
import { getConfig } from "./config";

class KeyMap extends Map<string, { algorithm: string; key: Buffer; }> {
	public random() {
		const entries = Array.from(this.entries()).map(([id, key]) => ({
			id,
			key: key.key,
			algorithm: key.algorithm
		}));

		return randomItem(entries);
	}
}

const CONFIG = getConfig();
const PRIVATE_KEYS = new KeyMap();
const PUBLIC_KEYS = new Map<string, string>();

export type RegisterRequest = Request & {
	query: {
		user_id: string;
	}
};

export const getRegisterJWT = function(req: RegisterRequest, res: Response) {
	if (req.query.user_id) {
		res.status(200).json({ jwt: sign("register", { user_id: req.query.user_id }) });
	} else {
		res.status(400).send({ error: "'user_id' query param is missing" });
	}
} as any as RequestHandler;

export type EarnRequest = Request & {
	query: {
		user_id: string;
		offer_id: string;
	}
};

export const getEarnJWT = function(req: EarnRequest, res: Response) {
	if (req.query.offer_id && req.query.user_id) {
		const offer = getOffer(req.query.offer_id);

		if (!offer) {
			res.status(400).send({ error: `cannot find offer with id '${ req.query.offer_id }'` });
		} else if (offer.type !== "earn") {
			res.status(400).send({ error: "requested offer is not an earn one" });
		} else {
			res.status(200).json({
				jwt: sign("earn", {
					offer: { id: offer.id, amount: offer.amount },
					recipient: { user_id: req.query.user_id, title: offer.title, description: offer.description }
				})
			});
		}
	} else {
		res.status(400).send({ error: "'offer_id' and/or 'user_id' query param is missing" });
	}
} as any as RequestHandler;

export type SpendRequest = Request & {
	query: {
		offer_id: string;
	}
};

export const getSpendJWT = function(req: SpendRequest, res: Response) {
	if (req.query.offer_id) {
		const offer = getOffer(req.query.offer_id);

		if (!offer) {
			res.status(400).send({ error: `cannot find offer with id '${ req.query.offer_id }'` });
		} else if (offer.type !== "spend") {
			res.status(400).send({ error: "requested offer is not a spend one" });
		} else {
			const payload = {
				offer: { id: offer.id, amount: offer.amount },
				sender: { title: offer.title, description: offer.description }
			};
			if (req.query.user_id) {
				Object.assign(payload.sender, { user_id: req.query.user_id });
			}

			res.status(200).json({ jwt: sign("spend", payload) });
		}
	} else {
		res.status(400).send({ error: "'offer_id' query param is missing" });
	}
} as any as RequestHandler;

export type PayToUserRequest = Request & {
	query: {
		sender_id: string;
		recipient_id: string;
		offer_id: string;
	}
};

export const getPayToUserJWT = function(req: PayToUserRequest, res: Response) {
	if (req.query.offer_id && req.query.recipient_id) {
		const offer = getOffer(req.query.offer_id);

		if (!offer) {
			res.status(400).send({ error: `cannot find offer with id '${req.query.offer_id}'` });
		} else if (offer.type !== "pay_to_user") {
			res.status(400).send({ error: "requested offer is not a pay to user one" });
		} else {
			const payload = {
				offer: { id: offer.id, amount: offer.amount },
				sender: { title: offer.title, description: offer.description },
				recipient: { user_id: req.query.recipient_id, title: offer.title, description: offer.description }
			};
			if (req.query.user_id) {
				Object.assign(payload.sender, { user_id: req.query.user_id });
			}

			res.status(200).json({ jwt: sign("pay_to_user", payload) });
		}
	} else {
		res.status(400).send({ error: "'offer_id' and/or 'recipient_id' query param is missing" });
	}
} as any as RequestHandler;

export const getOffers = function(req: Request, res: Response) {
	res.status(200).send({ offers: CONFIG.offers });
} as any as RequestHandler;

export type ArbitraryPayloadRequest = Request & {
	body: {
		subject: string;
		payload: { [key: string]: any };
	}
};

export const signArbitraryPayload = function(req: ArbitraryPayloadRequest, res: Response) {
	if (req.body.subject && req.body.payload) {
		res.status(200).json({ jwt: sign(req.body.subject, req.body.payload) });
	} else {
		res.status(400).send({ error: `missing 'subject' and/or 'payload' in request body` });
	}
} as any as RequestHandler;

export type P2pTransferRequest = Request & {
	body: {
		offer_id: string;
		amount: string;
		sender_title: string;
		sender_description: string;
		sender_id: string;
		recipient_title: string;
		recipient_description: string;
		recipient_id: string;
	}
};

export const getP2pTransferJWT = function(req: P2pTransferRequest, res: Response) {
	if (req.body.offer_id && req.body.amount 
		&& req.body.sender_title && req.body.sender_description && req.body.sender_id 
		&& req.body.recipient_title && req.body.recipient_description && req.body.recipient_id) {

		getDefaultLogger().info(req.body);

		const payload = {
			offer: { id: req.body.offer_id, amount: req.body.amount},
			sender: { title: req.body.sender_title, description: req.body.sender_description, user_id: req.body.sender_id },
			recipient: { title: req.body.recipient_title, description: req.body.recipient_description, user_id: req.body.recipient_id }
		}

		res.status(200).json({ jwt: sign("pay_to_user", payload)});
	} else {
		res.status(500).send({ error: " missing parameter" });
	}
} as any as RequestHandler;

export type GetPaymentToken = Request & {
	body: {
		offer_id: string;
		amount: string;
		user_id: string;
		title: string;
		description: string;
	}
};

export const getPaymentToken = function(req: GetPaymentToken, res: Response) {
	if (req.body.offer_id 
		&& req.body.amount 
		&& req.body.user_id 
		&& req.body.title 
		&& req.body.description) {		
		const payload = {
			offer: { id: req.body.offer_id, amount: req.body.amount},
			recipient: { title: req.body.title, description: req.body.description, user_id: req.body.user_id}
		}

		res.status(200).json({ jwt: sign("earn", payload)});
	} else {

	}
} as any as RequestHandler;

export type ValidateRequest = Request & {
	query: {
		jwt: string;
	}
};

export type JWTContent = {
	header: {
		typ: string;
		alg: string;
		kid: string;
	};
	payload: any;
	signature: string;
};

async function getPublicKey(kid: string): Promise<string> {
	let publicKey = PUBLIC_KEYS.get(kid);
	if (publicKey) {
		getDefaultLogger().info(`found public key ${kid} locally`);
	} else if (CONFIG.marketplace_service) {
		// try to get key from marketplace service
		const res = await axios.default.get(`${CONFIG.marketplace_service}/v1/config`);
		for (const key of Object.keys(res.data.jwt_keys)) {
			PUBLIC_KEYS.set(key, res.data.jwt_keys[key].key);
		}
		publicKey = PUBLIC_KEYS.get(kid);
		if (publicKey) {
			getDefaultLogger().info(`found public key ${kid} from remote`);
		}
	}
	if (!publicKey) {
		getDefaultLogger().error(`did not find public key ${kid}`);
		throw new Error(`no key for kid ${kid}`);
	}
	return publicKey;
}

export const validateJWT = async function(req: ValidateRequest, res: Response) {
	const decoded = jsonwebtoken.decode(req.query.jwt, { complete: true }) as JWTContent;
	try {
		const publicKey = await getPublicKey(decoded.header.kid);
		jsonwebtoken.verify(req.query.jwt, publicKey); // throws
		res.status(200).json({ is_valid: true });
	} catch (e) {
		res.status(200).json({ is_valid: false, error: e });
	}
} as any as RequestHandler;

function sign(subject: string, payload: any) {
	const signWith = PRIVATE_KEYS.random();

	payload = Object.assign({
		iss: getConfig().app_id,
		exp: moment().add(6, "hours").unix(),
		iat: moment().unix(),
		sub: subject
	}, payload);

	return jsonwebtoken.sign(payload, signWith.key, {
		header: {
			kid: signWith.id,
			alg: signWith.algorithm,
			typ: "JWT"
		}
	});
}

function getOffer(id: string): any | null {
	for (const offer of CONFIG.offers) {
		if (offer.id === id) {
			return offer;
		}
	}

	return null;
}

// init
(() => {
	Object.entries(CONFIG.private_keys).forEach(([name, key]) => {
		PRIVATE_KEYS.set(name, { algorithm: key.algorithm, key: readFileSync(path(key.file)) });
	});
	Object.entries(CONFIG.public_keys).forEach(([name, key]) => {
		PUBLIC_KEYS.set(name, readFileSync(path(key), "utf-8"));
	});
})();
