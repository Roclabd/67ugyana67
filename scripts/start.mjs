import { spawn, spawnSync } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const windows = process.platform === 'win32';
const args = process.argv.slice(2);
const javaHome = process.env.JAVA_HOME?.replace(/^"(.*)"$/, '$1');

function build(label, command, parameters, cwd, env) {
    console.log(label);
    // Windows batch files need cmd.exe. Commands and arguments below are fixed.
    const result = spawnSync(command, parameters, { cwd, env, stdio: 'inherit', shell: windows });
    if (result.error || result.status !== 0) {
        throw new Error(result.error?.message ?? label + ' завершилась с кодом ' + result.status);
    }
}

function javaTool(name) {
    const executable = windows ? name + '.exe' : name;
    return javaHome ? resolve(javaHome, 'bin', executable) : executable;
}

function java21(name) {
    const tool = javaTool(name);
    const result = spawnSync(tool, ['-version'], { encoding: 'utf8' });
    const version = (result.stdout ?? '') + (result.stderr ?? '');
    if (result.status !== 0 || !/(?:version "|javac )21(?:[.+-]|["\s]|$)/.test(version)) {
        throw new Error('Нужен JDK 21. Укажите JAVA_HOME на каталог JDK 21 или добавьте java и javac из JDK 21 в PATH.');
    }
    return tool;
}

function openBrowser(url) {
    const command = windows ? 'rundll32.exe' : process.platform === 'darwin' ? 'open' : 'xdg-open';
    const parameters = windows ? ['url.dll,FileProtocolHandler', url] : [url];
    const browser = spawn(command, parameters, { stdio: 'ignore', windowsHide: true });
    const instructions = () => console.log('Откройте адрес в браузере вручную: ' + url);
    browser.once('error', instructions);
    browser.once('exit', code => { if (code !== 0) instructions(); });
    browser.unref();
}

function serve(java, jar, env) {
    const child = spawn(java, ['-jar', jar, '--server.address=127.0.0.1'], {
        cwd: root, env, stdio: ['inherit', 'pipe', 'inherit'],
    });
    const lines = createInterface({ input: child.stdout });
    let url;
    let ready = false;
    let interrupted = false;
    const timeout = setTimeout(() => {
        console.error('Сервер не запустился за 120 секунд. Проверьте сообщения Java выше.');
        child.kill();
    }, 120_000);
    const stop = () => {
        interrupted = true;
        // On Windows the console sends Ctrl+C to Java as well.
        if (!windows) child.kill('SIGTERM');
    };
    process.once('SIGINT', stop);
    function cleanup() {
        clearTimeout(timeout);
        lines.close();
        process.removeListener('SIGINT', stop);
    }
    child.once('error', error => {
        cleanup();
        console.error('Не удалось запустить Java: ' + error.message);
        process.exitCode = 1;
    });
    child.once('close', code => {
        cleanup();
        if (!ready && !interrupted) console.error('Сервер остановился до запуска. Проверьте сообщения Java выше.');
        process.exitCode = interrupted ? 130 : code ?? 1;
    });
    lines.on('line', line => {
        console.log(line);
        const listener = line.match(/\bTomcat started on port (\d+) \((https?)\)/);
        if (listener && Number(listener[1]) > 0) url = listener[2] + '://127.0.0.1:' + listener[1];
        if (!ready && url && /\bStarted (?:\S+\.)?ApplicationKt in /.test(line)) {
            ready = true;
            clearTimeout(timeout);
            console.log('Откройте ' + url + ' · Для остановки нажмите Ctrl+C.');
            if (!args.includes('--no-browser')) openBrowser(url);
        }
    });
}

try {
    if (args.some(arg => arg !== '--no-browser')) throw new Error('Допустимый параметр: --no-browser.');
    const nodeMajor = Number(process.versions.node.split('.')[0]);
    if (nodeMajor < 20) throw new Error('Нужен Node.js версии 20 или новее с npm.');
    const java = java21('java');
    java21('javac');
    const env = { ...process.env, ...(javaHome ? { JAVA_HOME: javaHome } : {}) };
    const frontend = resolve(root, 'frontend');
    const npm = windows ? 'npm.cmd' : 'npm';
    build('Устанавливаю зависимости фронтенда.', npm, ['ci'], frontend, env);
    build('Собираю фронтенд.', npm, ['run', 'build'], frontend, env);
    build('Собираю JAR.', windows ? 'gradlew.bat' : './gradlew',
        ['--console=plain', '-PoneClickLaunch', ':backend:app:bootJar'], root, env);

    const jar = resolve(root, 'backend/app/build/libs/codeguard-launch.jar');
    accessSync(jar, constants.R_OK);
    serve(java, jar, env);
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
}
