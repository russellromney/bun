import { spawnSync } from "bun";
import { describe, expect, test } from "bun:test";
import { bunEnv, bunExe } from "harness";

// `console.table` and `Bun.inspect.table` share the same native TablePrinter,
// so we can render in-process instead of spawning a subprocess per case.
// Two differences to mirror so the existing snapshots stay valid:
//   1. When the first argument is not an object, `console.table` falls back to
//      `console.log`-style formatting, whereas `Bun.inspect.table` returns "".
//   2. `console.table` formats cell values starting at depth 0, whereas
//      `Bun.inspect.table` starts at `max_depth` (5). Pass `{ depth: 0 }`
//      explicitly so nested objects in cells render the same way.
function renderTable(...args: any[]): string {
  const [data, properties] = args;
  if (typeof data !== "object" || data === null) {
    // console.log(x): bare strings print raw, everything else is inspected.
    return (typeof data === "string" ? data : Bun.inspect(data)) + "\n";
  }
  return properties === undefined
    ? Bun.inspect.table(data, { depth: 0 })
    : Bun.inspect.table(data, properties, { depth: 0 });
}

describe("console.table", () => {
  test("throws when second arg is invalid", () => {
    expect(() => console.table({})).not.toThrow();
    expect(() => console.table({}, [])).not.toThrow();
    // @ts-expect-error
    expect(() => console.table({}, "invalid")).toThrow();
  });

  const cases: [string, { args: () => any[] }][] = [
    [
      "not object (number)",
      {
        args: () => [42],
      },
    ],
    [
      "not object (string)",
      {
        args: () => ["bun"],
      },
    ],
    [
      "object - empty",
      {
        args: () => [{}],
      },
    ],
    [
      "object",
      {
        args: () => [{ a: 42, b: "bun" }],
      },
    ],
    [
      "array - empty",
      {
        args: () => [[]],
      },
    ],
    [
      "array - plain",
      {
        args: () => [[42, "bun"]],
      },
    ],
    [
      "array - object",
      {
        args: () => [[{ a: 42, b: "bun" }]],
      },
    ],
    [
      "array - objects with diff props",
      {
        args: () => [[{ b: "bun" }, { a: 42 }]],
      },
    ],
    [
      "array - mixed",
      {
        args: () => [[{ a: 42, b: "bun" }, 42]],
      },
    ],
    [
      "set",
      {
        args: () => [new Set([42, "bun"])],
      },
    ],
    [
      "map",
      {
        args: () => [
          new Map<any, any>([
            ["a", 42],
            ["b", "bun"],
            [42, "c"],
          ]),
        ],
      },
    ],
    [
      "properties",
      {
        args: () => [[{ a: 42, b: "bun" }], ["b", "c", "a"]],
      },
    ],
    [
      "properties - empty",
      {
        args: () => [[{ a: 42, b: "bun" }], []],
      },
    ],
    [
      "properties - interesting character",
      {
        args: () => [
          {
            a: "_字",
          },
        ],
      },
    ],
    [
      "values - array",
      {
        args: () => [
          [
            { value: { a: 42, b: "bun" } },
            { value: [42, "bun"] },
            { value: new Set([42, "bun"]) },
            {
              value: new Map<any, any>([
                [42, "bun"],
                ["bun", 42],
              ]),
            },
          ],
        ],
      },
    ],
    [
      "headers object",
      {
        args: () => [
          new Headers([
            ["abc", "bun"],
            ["potato", "tomato"],
          ]),
        ],
      },
    ],
    [
      "number keys",
      {
        args: () => [{ test: { "10": 123, "100": 154 } }],
      },
    ],
  ];

  test.each(cases)("expected output for: %s", (label, { args }) => {
    const actualOutput = renderTable(...args());
    expect(actualOutput).toMatchSnapshot();
  });
});

test("console.table json fixture", () => {
  const actualOutput = renderTable(require("./console-table-json-fixture.json"))
    // todo: fix bug causing this to be necessary:
    .replaceAll("`", "'");
  expect(actualOutput).toMatchSnapshot();
});

function ansify(str: string) {
  return `\u001b[31m${str}\u001b[39m`;
}
const ansiObj = {
  [ansify("hello")]: ansify("this is a long string with ansi color codes"),
  [ansify("world")]: ansify("this is another long string with ansi color"),
  [ansify("foo")]: ansify("bar"),
};
test("console.table ansi colors", () => {
  const actualOutput = renderTable(ansiObj)
    // todo: fix bug causing this to be necessary:
    .replaceAll("`", "'");
  expect(actualOutput).toMatchSnapshot();
});

test.skip("console.table character widths", () => {
  // note: this test cannot be automated because cannot test printed witdhs consistently.
  // so this test is just meant to be run manually

  // top ~2000 most used unicode codepoints
  const str = `~!@#$%^&*()_-+={[}]|:;"'<,>.?/¡¢£¤¥¦§¨©ª«¬ ®¯°±²³´µ¶·¸ʻ¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿŁłŃńŅņŇňŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŴŵŶŷŸŹźŻżŽžſƆƎƜɐɑɒɔɘəɛɜɞɟɡɢɣɤɥɨɪɬɮɯɰɴɵɶɷɸɹʁʇʌʍʎʞΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρςστυφχψωАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяᴀᴁᴂᴃᴄᴅᴆᴇᴈᴉᴊᴋᴌᴍᴎᴏᴐᴑᴒᴓᴔᴕᴖᴗᴘᴙᴚᴛᴜᴝᴞᴟᴠᴡᴢᴣᴤᴥᴦᴧᴨᴩᴪẞỲỳỴỵỸỹ‐‑‒–—―‖‗‘’‚‛“”„‟†‡•‣․‥…‧‰‱′″‴‵‶‷‸‹›※‼‽‾‿⁀⁁⁂⁃⁄⁅⁆⁇⁈⁉⁊⁋⁌⁍⁎⁏⁐⁑⁒⁓⁔⁕⁗⁰ⁱ⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾ⁿ₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎₠₡₢₣₤₥₦₧₨₩₪₫€₭₮₯₰₱₲₳₴₵₶₷₸₹℀℁ℂ℃℄℅℆ℇ℈℉ℊℋℌℍℎℏℐℑℒℓ℔ℕ№℗℘ℙℚℛℜℝ℞℟℠℡™℣ℤ℥Ω℧ℨ℩Åℬℭ℮ℯℰℱℲℳℴℵℶℷℸ⅁⅂⅃⅄ⅅⅆⅇⅈⅉ⅋ⅎ⅐⅑⅒⅓⅔⅕⅖⅗⅘⅙⅚⅛⅜⅝⅞⅟ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩⅪⅫⅬⅭⅮⅯⅰⅱⅲⅳⅴⅵⅶⅷⅸⅹⅺⅻⅼⅽⅾⅿↄ←↑→↓↔↕↖↗↘↙↚↛↜↝↞↟↠↡↢↣↤↥↦↧↨↩↪↫↬↭↮↯↰↱↲↳↴↵↶↷↸↹↺↻↼↽↾↿⇀⇁⇂⇃⇄⇅⇆⇇⇈⇉⇊⇋⇌⇍⇎⇏⇐⇑⇒⇓⇔⇕⇖⇗⇘⇙⇚⇛⇜⇝⇞⇟⇠⇡⇢⇣⇤⇥⇦⇧⇨⇩⇪⇫⇬⇭⇮⇯⇰⇱⇲⇳⇴⇵⇶⇷⇸⇹⇺⇻⇼⇽⇾⇿∀∁∂∃∄∅∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿≀≁≂≃≄≅≆≇≈≉≊≋≌≍≎≏≐≑≒≓≔≕≖≗≘≙≚≛≜≝≞≟≠≡≢≣≤≥≦≧≨≩≪≫≬≭≮≯≰≱≲≳≴≵≶≷≸≹≺≻≼≽≾≿⊀⊁⊂⊃⊄⊅⊆⊇⊈⊉⊊⊋⊌⊍⊎⊏⊐⊑⊒⊓⊔⊕⊖⊗⊘⊙⊚⊛⊜⊝⊞⊟⊠⊡⊢⊣⊤⊥⊦⊧⊨⊩⊪⊫⊬⊭⊮⊯⊰⊱⊲⊳⊴⊵⊶⊷⊸⊹⊺⊻⊼⊽⊾⊿⋀⋁⋂⋃⋄⋅⋆⋇⋈⋉⋊⋋⋌⋍⋎⋏⋐⋑⋒⋓⋔⋕⋖⋗⋘⋙⋚⋛⋜⋝⋞⋟⋠⋡⋢⋣⋤⋥⋦⋧⋨⋩⋪⋫⋬⋭⋮⋯⋰⋱⌀⌁⌂⌃⌄⌅⌆⌇⌈⌉⌊⌋⌐⌑⌒⌓⌔⌕⌖⌗⌘⌙⌚⌛⌠⌡⌢⌣⌤⌥⌦⌧⌨⌫⌬⎛⎜⎝⎞⎟⎠⎡⎢⎣⎤⎥⎦⎧⎨⎩⎪⎫⎬⎭⏎⏏⏚⏛⏰⏱⏲⏳␢␣─━│┃┄┅┆┇┈┉┊┋┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┯┰┱┲┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋╌╍╎╏═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬╭╮╯╰╱╲╳╴╵╶╷╸╹╺╻╼╽╾╿▀▁▂▃▄▅▆▇█▉▊▋▌▍▎▏▐░▒▓▔▕▖▗▘▙▚▛▜▝▞▟■□▢▣▤▥▦▧▨▩▪▫▬▭▮▯▰▱▲△▴▵▶▷▸▹►▻▼▽▾▿◀◁◂◃◄◅◆◇◈◉◊○◌◍◎●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯◰◱◲◳◴◵◶◷◸◹◺◻◼◽◾◿☀☁☂☃☄★☆☇☈☉☊☋☌☍☎☏☐☑☒☓☔☕☖☗☘☙☚☛☜☝☞☟☠☡☢☣☤☥☦☧☨☩☪☫☬☭☮☯☰☱☲☳☴☵☶☷☸☹☺☻☼☽☾☿♀♁♂♃♄♅♆♇♈♉♊♋♌♍♎♏♐♑♒♓♔♕♖♗♘♙♚♛♜♝♞♟♠♡♢♣♤♥♦♧♨♩♪♫♬♭♮♯♲♳♴♵♶♷♸♹♺♻♼♽♾♿⚀⚁⚂⚃⚄⚅⚐⚑⚒⚓⚔⚕⚖⚗⚘⚙⚚⚛⚜⚝⚞⚟⚠⚡⚢⚣⚤⚥⚦⚧⚨⚩⚪⚫⚬⚭⚮⚯⚰⚱⚲⚳⚴⚵⚶⚷⚸⚹⚺⚻⚼⛀⛁⛂⛃⛢⛤⛥⛦⛧⛨⛩⛪⛫⛬⛭⛮⛯⛰⛱⛲⛳⛴⛵⛶⛷⛸⛹⛺⛻⛼⛽⛾⛿✁✂✃✄✅✆✇✈✉✊✋✌✍✎✏✐✑✒✓✔✕✖✗✘✙✚✛✜✝✞✟✠✡✢✣✤✥✦✧✨✩✪✫✬✭✮✯✰✱✲✳✴✵✶✷✸✹✺✻✼✽✾✿❀❁❂❃❄❅❆❇❈❉❊❋❌❍❎❏❐❑❒❓❔❕❖❗❘❙❚❛❜❝❞❟❠❡❢❣❤❥❦❧➔➘➙➚➛➜➝➞➟➠➡➢➣➤➥➦➧➨➩➪➫➬➭➮➯➱➲➳➴➵➶➷➸➹➺➻➼➽➾⟰⟱⟲⟳⟴⟵⟶⟷⟸⟹⟺⟻⟼⟽⟾⟿⤀⤁⤂⤃⤄⤅⤆⤇⤈⤉⤊⤋⤌⤍⤎⤏⤐⤑⤒⤓⤔⤕⤖⤗⤘⤙⤚⤛⤜⤝⤞⤟⤠⤡⤢⤣⤤⤥⤦⤧⤨⤩⤪⤫⤬⤭⤮⤯⤰⤱⤲⤳⤴⤵⤶⤷⤸⤹⤺⤻⤼⤽⤾⤿⥀⥁⥂⥃⥄⥅⥆⥇⥈⥉⥊⥋⥌⥍⥎⥏⥐⥑⬀⬁⬂⬃⬄⬅⬆⬇⬈⬉⬊⬋⬌⬍⬎⬏⬐⬑⬒⬓⬔⬕⬖⬗⬘⬙⬚ⱠⱡⱣⱥⱦⱭⱯⱰ⸢⸣⸤⸥⸮〃〄ﬀﬁﬂﬃﬄﬅﬆ﴾﴿﷼︐︑︒︓︔︕︖︗︘︙︰︱︲︳︴︵︶︷︸︹︺︻︼︽︾︿﹀﹁﹂﹃﹄﹅﹆﹉﹊﹋﹌﹍﹎﹏﹐﹑﹒﹔﹕﹖﹗﹘﹙﹚﹛﹜﹝﹞﹟﹠﹡﹢﹣﹤﹥﹦﹨﹩﹪﹫\ufeff！＂＃＄％＆＇（）＊＋，－．／０１２３４５６７８９：；＜＝＞？＠ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ［＼］＾＿｀ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ｛｜｝～｟｠￠￡￢￣￤￥￦￼�`;
  const { stdout } = spawnSync({
    cmd: [bunExe(), "-e", `console.table(${JSON.stringify([...str.matchAll(/.{16}|.+/g)].map(g => g[0].split("")))})`],
    stdout: "pipe",
    stderr: "inherit",
    env: bunEnv,
  });
  const actualOutput = stdout.toString();

  console.log(actualOutput);
});

test("console.table repeat 50", () => {
  const expected = `┌─────────┬───┐
│ (index) │ n │
├─────────┼───┤
│ 0       │ 8 │
└─────────┴───┘
`;
  for (let i = 0; i < 50; i++) {
    expect(renderTable([{ n: 8 }])).toBe(expected);
  }
});

// https://github.com/oven-sh/bun/issues/32614
// Node labels the first column "(index)" ("(iteration index)" for Map/Set) and
// left-aligns it; Bun left the header blank and right-aligned the column. These
// drive the real `console.table` / `node:console` path through a subprocess.
describe.concurrent("Node compatibility: index column header + alignment", () => {
  async function run(code: string): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
    await using proc = Bun.spawn({
      cmd: [bunExe(), "-e", code],
      env: bunEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
    return { stdout, stderr, exitCode };
  }

  test("array of objects: (index) header, left-aligned index column", async () => {
    const { stdout, exitCode } = await run(`console.table([{ a: 1, b: 'Y' }, { a: 'Z', b: 2 }]);`);
    expect(stdout).toBe(
      `┌─────────┬───┬───┐
│ (index) │ a │ b │
├─────────┼───┼───┤
│ 0       │ 1 │ Y │
│ 1       │ Z │ 2 │
└─────────┴───┴───┘
`,
    );
    expect(exitCode).toBe(0);
  });

  test("`table` from node:console matches global console.table", async () => {
    const input = `[{ a: 1, b: 'Y' }, { a: 'Z', b: 2 }]`;
    const { stdout: fromImport, exitCode: importExitCode } = await run(
      `import { table } from 'node:console'; table(${input});`,
    );
    const { stdout: fromGlobal, exitCode: globalExitCode } = await run(`console.table(${input});`);
    expect(fromImport).toBe(fromGlobal);
    expect(fromImport).toContain("(index)");
    expect(importExitCode).toBe(0);
    expect(globalExitCode).toBe(0);
  });

  test("plain object uses (index) header", async () => {
    const { stdout, exitCode } = await run(`console.table({ a: 42, b: 'bun' });`);
    expect(stdout).toBe(
      `┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ a       │ 42     │
│ b       │ bun    │
└─────────┴────────┘
`,
    );
    expect(exitCode).toBe(0);
  });

  test("Map uses (iteration index) header", async () => {
    const { stdout, exitCode } = await run(`console.table(new Map([['a', 42], ['b', 'bun'], [42, 'c']]));`);
    expect(stdout).toBe(
      `┌───────────────────┬─────┬────────┐
│ (iteration index) │ Key │ Values │
├───────────────────┼─────┼────────┤
│ 0                 │ a   │ 42     │
│ 1                 │ b   │ bun    │
│ 2                 │ 42  │ c      │
└───────────────────┴─────┴────────┘
`,
    );
    expect(exitCode).toBe(0);
  });

  test("Set uses (iteration index) header", async () => {
    const { stdout, exitCode } = await run(`console.table(new Set([42, 'bun']));`);
    expect(stdout).toBe(
      `┌───────────────────┬────────┐
│ (iteration index) │ Values │
├───────────────────┼────────┤
│ 0                 │ 42     │
│ 1                 │ bun    │
└───────────────────┴────────┘
`,
    );
    expect(exitCode).toBe(0);
  });

  // WeakMap/WeakSet are not iterable, so Node renders them as plain objects
  // with the "(index)" header (not "(iteration index)", and no "Key" column).
  test.each([
    ["WeakMap", "new WeakMap()"],
    ["WeakSet", "new WeakSet()"],
  ])("%s uses (index) header like a plain object", async (_label, expr) => {
    const { stdout, exitCode } = await run(`console.table(${expr});`);
    expect(stdout).toBe(
      `┌─────────┐
│ (index) │
├─────────┤
└─────────┘
`,
    );
    expect(exitCode).toBe(0);
  });
});
