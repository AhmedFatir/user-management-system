import React, { useRef, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import "./bot.css";
import ScoreBoard from '../components/ScoreBoard';
import Timeout from '../components/TimeOut';
import avatar from "../asstes/avatar3.png";
import pongy from "../asstes/pongy.png";
import exit from "../asstes/right-arrow.png";
import { useTranslation } from 'react-i18next'


const GameLogic = ({paddleColor, keys, username}) => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const canvasRef = useRef(null);
    const userRef = useRef({
            x: 20,
            y: 0,
            width: 10,
            height: 140,
            score: 0,
            color: paddleColor,
        });
        
    const [userScore, setUserScore] = useState(0);
    const [comScore, setComScore] = useState(0);
    const [gameRunning, setGameRunning] = useState(true);
    const [showExitPopup, setShowExitPopup] = useState(false);
    const [pauseGame, setPauseGame] = useState(false);

    const handleUserScore = (score) => {
        setUserScore(score);
    };

    const handleComScore = (score) => {
        setComScore(score);
    };

    useEffect(() => {
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        const user = userRef.current;
        canvas.width = 1384;
        canvas.height = 696;
        const ball = {
            x: canvas.width / 2,
            y: canvas.height / 2,
            radius: 10,
            velocityX: 5,
            velocityY: 5,
            speed: 7,
            color: "WHITE"
        };

        const com = {
            x: canvas.width - 30,
            y: (canvas.height - 140) / 2,
            width: 10,
            height: 140,
            score: 0,
            color: "#3357FF"
        };

        const net = {
            x: (canvas.width - 2) / 2,
            y: 0,
            height: 10,
            width: 2,
            color: "#D9D9D9"
        };

        function drawRect(x, y, w, h, color) {
            ctx.fillStyle = color;
            ctx.fillRect(x, y, w, h);
        }

        function drawArc(x, y, r, color) {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(x, y, r, 0, Math.PI * 2, true);
            ctx.closePath();
            ctx.fill();
        }

        function handleKeyDown(evt) {
            if (keys === "ws") {
                switch (evt.key) {
                    case 'w':
                        if (user.y > 0) {
                            user.y -= 20;
                        }
                        break;
                    case 's':
                        if (user.y < canvas.height - user.height) {
                            user.y += 20;
                        }
                        break;
                    default:
                        break;
                }
            } else {
                switch (evt.key) {
                    case 'ArrowUp':
                        if (user.y > 0) {
                            user.y -= 20;
                        }
                        break;
                    case 'ArrowDown':
                        if (user.y < canvas.height - user.height) {
                            user.y += 20;
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        window.addEventListener('keydown', handleKeyDown);

        function resetBall() {
            ball.x = canvas.width / 2;
            ball.y = canvas.height / 2;
            ball.velocityX = -ball.velocityX;
            ball.speed = 7;
        }

        function drawNet() {
            for (let i = 0; i <= canvas.height; i ++) {
                drawRect(net.x, net.y + i, net.width, net.height, net.color);
            }
        }

        function collision(b, p) {
            p.top = p.y;
            p.bottom = p.y + p.height;
            p.left = p.x;
            p.right = p.x + p.width;

            b.top = b.y - b.radius;
            b.bottom = b.y + b.radius;
            b.left = b.x - b.radius;
            b.right = b.x + b.radius;

            return p.left < b.right && p.top < b.bottom && p.right > b.left && p.bottom > b.top;
        }

        function update() {
            if (ball.x - ball.radius < 0) {
                com.score++;
                handleComScore(com.score);
                resetBall();
            } else if (ball.x + ball.radius > canvas.width) {
                user.score++;
                handleUserScore(user.score);
                resetBall();
            }

            ball.x += ball.velocityX;
            ball.y += ball.velocityY;
            com.y += ((ball.y - (com.y + com.height / 2))) * 0.1;
            if (ball.y - ball.radius < 0 || ball.y + ball.radius > canvas.height) {
                ball.velocityY = -ball.velocityY;
            }
            const player = (ball.x + ball.radius < canvas.width / 2) ? user : com;
            if (collision(ball, player)) {
                let collidePoint = (ball.y - (player.y + player.height / 2));
                collidePoint = collidePoint / (player.height / 2);
                let angleRad = (Math.PI / 4) * collidePoint;
                let direction = (ball.x + ball.radius < canvas.width / 2) ? 1 : -1;
                ball.velocityX = direction * ball.speed * Math.cos(angleRad);
                ball.velocityY = ball.speed * Math.sin(angleRad);
                ball.speed += 0.1;
            }
        }

        function render() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = 'rgba(22, 22, 37, 0.9)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            drawNet();
            ctx.fillStyle = user.color;
            drawRoundedRect(user.x, user.y, user.width, user.height, 9);
            ctx.fillStyle = com.color;
            drawRoundedRect(com.x, com.y, com.width, com.height, 9);
            drawArc(ball.x, ball.y, ball.radius, ball.color);
        }

        function drawRoundedRect(x, y, width, height, radius) {
            ctx.beginPath();
            ctx.moveTo(x + radius, y);
            ctx.lineTo(x + width - radius, y);
            ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
            ctx.lineTo(x + width, y + height - radius);
            ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
            ctx.lineTo(x + radius, y + height);
            ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
            ctx.lineTo(x, y + radius);
            ctx.quadraticCurveTo(x, y, x + radius, y);
            ctx.closePath();
            ctx.fill();
        }

        function game() {
            if (!pauseGame) {
                update();
                render();
            }
        }

        let framePerSecond = 50;
        let loop = setInterval(game, 1000 / framePerSecond);

        const speedInterval = setInterval(() => {
            ball.speed += 1;
        }, 20000);

        return () => {
            clearInterval(loop);
            clearInterval(speedInterval);
            window.removeEventListener('keydown', handleKeyDown);
        };
    }, [paddleColor, keys, pauseGame]);

    const handleTimeout = () => {
        setGameRunning(false);
        alert("Game Timeout! Returning to lobby...");
    };

    const handleExitGame = () => {
        setPauseGame(true);
        setShowExitPopup(true);
    };

    const confirmExitGame = (confirm) => {
        setShowExitPopup(false);
        if (confirm) {
            setGameRunning(false);
        } else {
            setPauseGame(false);
        }
    };
    if (!gameRunning) {
        navigate('game');
        return;
    }
    return (
        <div className="pingponggame-container">
                    <div className="info-container">
                        <ScoreBoard
                            user1Score={userScore}
                            user2Score={comScore}
                            user1Name={username}
                            user1Avatar={avatar}
                            user2Name="PONGY!"
                            user2Avatar={pongy}
                        />
                        <Timeout onTimeout={handleTimeout} />
                    </div>
                <canvas className='canvas-container' ref={canvasRef}></canvas>
                <button className='exit-game-button' onClick={handleExitGame}><img src={exit} alt="" className='exit-logo'/></button>
                {showExitPopup && (
                    <div className="exit-popup">
                        <div className="exit-popup-content">
                            <h2>{t('BACK TO LOBBY ?')}</h2>
                            <div className="exit-popup-buttons">
                                <button onClick={() => confirmExitGame(true)}>{t('Yes')}</button>
                                <button onClick={() => confirmExitGame(false)}>{t('Cancel')}</button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
    );
}

export default GameLogic;