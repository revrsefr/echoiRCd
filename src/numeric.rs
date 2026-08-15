//! IRC numeric replies (RFC 1459/2812 subset) used by the core.

pub const RPL_MAP: u16 = 6;
pub const RPL_MAPEND: u16 = 7;
pub const RPL_STATSLINKINFO: u16 = 211; // STATS l — a server link
pub const RPL_STATSCOMMANDS: u16 = 212;
pub const RPL_ENDOFSTATS: u16 = 219;
pub const RPL_STATSUPTIME: u16 = 242;
pub const RPL_STATSOLINE: u16 = 243;
pub const RPL_STATSXLINE: u16 = 223; // K/G/Z-line listing
pub const RPL_ADMINME: u16 = 256;
pub const RPL_ADMINLOC1: u16 = 257;
pub const RPL_ADMINLOC2: u16 = 258;
pub const RPL_ADMINEMAIL: u16 = 259;
pub const RPL_USERHOST: u16 = 302;
pub const RPL_ISON: u16 = 303;
pub const RPL_WHOISIDLE: u16 = 317;
pub const RPL_WHOISSPECIAL: u16 = 320; // SWHOIS oper-set whois line
pub const RPL_LISTSTART: u16 = 321;
pub const RPL_LIST: u16 = 322;
pub const RPL_LISTEND: u16 = 323;
pub const RPL_WHOWASUSER: u16 = 314;
pub const RPL_ENDOFWHOWAS: u16 = 369;
pub const RPL_INFO: u16 = 371;
pub const RPL_ENDOFINFO: u16 = 374;
pub const RPL_REHASHING: u16 = 382;
pub const RPL_TIME: u16 = 391;
pub const ERR_NOSUCHSERVER: u16 = 402;
pub const ERR_WASNOSUCHNICK: u16 = 406;
pub const ERR_UNAVAILRESOURCE: u16 = 437; // channel temporarily unavailable (+j)
pub const ERR_LINKCHANNEL: u16 = 470; // +L — you were redirected to another channel
pub const ERR_DELAYREJOIN: u16 = 495; // +J — must wait before rejoining after a kick
pub const ERR_CANTSENDTOUSER: u16 = 531; // +c — no shared channel with the target
pub const ERR_BADCHANNEL: u16 = 926; // CBAN — this channel name is forbidden
pub const RPL_ENDOFSPAMFILTER: u16 = 940; // end of the +g word-filter list
pub const RPL_EXEMPTIONLIST: u16 = 954; // +X exemptchanops entry
pub const RPL_ENDOFEXEMPTIONLIST: u16 = 953; // end of the +X list
pub const RPL_AUTOOPLIST: u16 = 910; // +w autoop entry
pub const RPL_ENDOFAUTOOP: u16 = 911; // end of the +w list
pub const RPL_SPAMFILTER: u16 = 941; // one +g word-filter entry
pub const RPL_KNOCK: u16 = 710; // channel gets the knock
pub const RPL_KNOCKDLVR: u16 = 711; // knocker's ack

// SILENCE (server-side ignore list)
pub const RPL_SILELIST: u16 = 271;
pub const RPL_ENDOFSILENCE: u16 = 272;
pub const ERR_SILELISTFULL: u16 = 511;

// ACCEPT / callerid (umode +g)
pub const RPL_ACCEPTLIST: u16 = 281;
pub const RPL_ENDOFACCEPT: u16 = 282;
pub const ERR_ACCEPTFULL: u16 = 456;
pub const ERR_ACCEPTEXIST: u16 = 457;
pub const ERR_ACCEPTNOT: u16 = 458;
pub const RPL_TARGUMODEG: u16 = 716; // "<nick> :is in +g mode (server-side ignore)"
pub const RPL_TARGNOTIFY: u16 = 717; // "<nick> :has been informed that you messaged them"
pub const RPL_UMODEGMSG: u16 = 718; // to the +g user: "<nick> <user@host> :is messaging you…"

// WATCH (notify list)
pub const RPL_LOGON: u16 = 600;
pub const RPL_LOGOFF: u16 = 601;
pub const RPL_WATCHOFF: u16 = 602;
pub const RPL_WATCHSTAT: u16 = 603;
pub const RPL_NOWON: u16 = 604;
pub const RPL_NOWOFF: u16 = 605;
pub const RPL_WATCHLIST: u16 = 606;
pub const RPL_ENDOFWATCHLIST: u16 = 607;
pub const ERR_TOOMANYWATCH: u16 = 512;

// MONITOR (IRCv3 notify list)
pub const RPL_MONONLINE: u16 = 730;
pub const RPL_MONOFFLINE: u16 = 731;
pub const RPL_MONLIST: u16 = 732;
pub const RPL_ENDOFMONLIST: u16 = 733;
pub const ERR_MONLISTFULL: u16 = 734;

pub const RPL_WELCOME: u16 = 1;
pub const RPL_YOURHOST: u16 = 2;
pub const RPL_CREATED: u16 = 3;
pub const RPL_MYINFO: u16 = 4;
pub const RPL_ISUPPORT: u16 = 5;

pub const RPL_UMODEIS: u16 = 221;
pub const RPL_YOUREOPER: u16 = 381;
pub const ERR_PASSWDMISMATCH: u16 = 464;
pub const ERR_TOOMANYCHANNELS: u16 = 405;
pub const ERR_NOPRIVILEGES: u16 = 481;
pub const ERR_UMODEUNKNOWNFLAG: u16 = 501;
pub const RPL_LUSERCLIENT: u16 = 251;

pub const RPL_WHOISUSER: u16 = 311;
pub const RPL_WHOISSERVER: u16 = 312;
pub const RPL_ENDOFWHO: u16 = 315;
pub const RPL_WHOISCHANNELS: u16 = 319;
pub const RPL_ENDOFWHOIS: u16 = 318;
pub const RPL_WHOISOPERATOR: u16 = 313; // "is an IRC operator" (hidden by +H)
pub const RPL_WHOISBOT: u16 = 335; // "is a bot" (umode +B)
pub const RPL_WHOISACCOUNT: u16 = 330; // "<nick> <account> :is logged in as"
pub const RPL_WHOISREGNICK: u16 = 307; // "is a registered nick" (identified to an account)
pub const RPL_WHOISMODES: u16 = 379; // oper/self-only: "is using modes +<umodes>"
pub const RPL_SNOMASKIS: u16 = 8; // "+<mask> :Server notice mask" after a +s change
pub const ERR_NEEDREGGEDNICK: u16 = 477; // chan +R/+M — must be logged into an account
pub const RPL_WHOISHOST: u16 = 378; // oper-only: real host/ip behind a cloak
pub const RPL_WHOISSECURE: u16 = 671; // "is using a secure connection" (sslinfo)
pub const RPL_WHOISCERTFP: u16 = 276; // "has client certificate fingerprint <fp>"
pub const RPL_HOSTHIDDEN: u16 = 396; // "is now your displayed host" (cloak on/off)

pub const RPL_CHANNELMODEIS: u16 = 324;
pub const RPL_CREATIONTIME: u16 = 329;
pub const RPL_NOTOPIC: u16 = 331;
pub const RPL_TOPIC: u16 = 332;
pub const RPL_WHOREPLY: u16 = 352;
pub const RPL_WHOSPCRPL: u16 = 354; // WHOX: field-selected WHO reply
pub const RPL_KEYVALUE: u16 = 761; // draft/metadata-2: <target> <key> <vis> :<value>
pub const RPL_KEYNOTSET: u16 = 766; // draft/metadata-2: key not set
pub const RPL_NAMREPLY: u16 = 353;
pub const RPL_ENDOFNAMES: u16 = 366;

pub const RPL_MOTD: u16 = 372;
pub const RPL_MOTDSTART: u16 = 375;
pub const RPL_ENDOFMOTD: u16 = 376;
pub const RPL_LINKS: u16 = 364;
pub const RPL_ENDOFLINKS: u16 = 365;

pub const ERR_NOSUCHNICK: u16 = 401;
pub const ERR_BADRELAYNICK: u16 = 573; // RELAYMSG: bad/taken spoofed nick
pub const ERR_NOSUCHCHANNEL: u16 = 403;
pub const ERR_CANNOTSENDTOCHAN: u16 = 404;
pub const ERR_NORECIPIENT: u16 = 411;
pub const ERR_NOTEXTTOSEND: u16 = 412;
pub const ERR_UNKNOWNCOMMAND: u16 = 421;
pub const ERR_NOMOTD: u16 = 422;
pub const ERR_NONICKNAMEGIVEN: u16 = 431;
pub const ERR_ERRONEUSNICKNAME: u16 = 432;
pub const ERR_NICKNAMEINUSE: u16 = 433;
pub const ERR_USERNOTINCHANNEL: u16 = 441;
pub const ERR_NOTONCHANNEL: u16 = 442;
pub const ERR_CHANNELISFULL: u16 = 471;
pub const ERR_UNKNOWNMODE: u16 = 472;
pub const ERR_INVITEONLYCHAN: u16 = 473;
pub const ERR_BADCHANNELKEY: u16 = 475;
pub const ERR_CHANOPRIVSNEEDED: u16 = 482;
pub const ERR_SECUREONLYCHAN: u16 = 489; // can't join a +z channel without TLS
pub const ERR_ALLMUSTSSL: u16 = 490; // can't set +z while a member isn't on TLS
pub const ERR_NOTREGISTERED: u16 = 451;
pub const ERR_NEEDMOREPARAMS: u16 = 461;
pub const ERR_ALREADYREGISTERED: u16 = 462;
pub const ERR_USERSDONTMATCH: u16 = 502;

pub const RPL_AWAY: u16 = 301;
pub const RPL_UNAWAY: u16 = 305;
pub const RPL_NOWAWAY: u16 = 306;
pub const RPL_INVITING: u16 = 341;
pub const RPL_BANLIST: u16 = 367;
pub const RPL_ENDOFBANLIST: u16 = 368;
pub const RPL_INVEXLIST: u16 = 346;
pub const RPL_ENDOFINVEXLIST: u16 = 347;
pub const RPL_EXCEPTLIST: u16 = 348;
pub const RPL_ENDOFEXCEPTLIST: u16 = 349;
pub const ERR_CANTCHANGENICK: u16 = 447; // +N — no nick change on channel
pub const ERR_CANTJOINOPERSONLY: u16 = 520; // +O — IRC operators only
pub const ERR_USERONCHANNEL: u16 = 443;
pub const ERR_BANNEDFROMCHAN: u16 = 474;

// SASL (IRCv3)
pub const RPL_LOGGEDIN: u16 = 900;
pub const RPL_LOGGEDOUT: u16 = 901;
pub const ERR_NICKLOCKED: u16 = 902;
pub const RPL_SASLSUCCESS: u16 = 903;
pub const ERR_SASLFAIL: u16 = 904;
pub const ERR_SASLTOOLONG: u16 = 905;
pub const ERR_SASLABORTED: u16 = 906;
pub const RPL_SASLMECHS: u16 = 908;
