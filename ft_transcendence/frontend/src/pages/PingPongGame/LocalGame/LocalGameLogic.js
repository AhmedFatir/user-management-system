import React, { useRef, useEffect, useState, useCallback } from 'react';
import useFetch from '../../../hooks/useFetch';
import { useNavigate } from 'react-router-dom';
import ScoreBoard from '../components/ScoreBoard';
import exit from "../asstes/right-arrow.png";
import { useTranslation } from 'react-i18next'
import Loading from '../components/Loading';
import AboutLocalGame from '../components/AboutLocalGame';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const LocalGameLogic = ({ player1Id, player2Id, handleEndMatch }) => {
    const { data: player1, isLoading: isLoadingPlayer1, error: player1Error } = useFetch(`${BACKEND_URL}/user/local-player/${player1Id}`);
    const { data: player2, isLoading: isLoadingPlayer2, error: player2Error } = useFetch(`${BACKEND_URL}/user/local-player/${player2Id}`);
    const navigate = useNavigate();
    const canvasRef = useRef(null);
    const { t } = useTranslation();

    const [showAboutGame, setShowAboutGame] = useState(true);
    const [user1Score, setUser1Score] = useState(0);
    const [user2Score, setUser2Score] = useState(0);
    const [gameRunning, setGameRunning] = useState(false);
    const [matchRunning, setMatchRunning] = useState(false);
    const [gameOver, setGameOver] = useState(false);
    const [canvasSize, setCanvasSize] = useState({ width: 1384, height: 696 });

    const [keyState, setKeyState] = useState({
        ArrowUp: false,
        ArrowDown: false,
        w: false,
        s: false
    });

    const user1Ref = useRef({
        x: 20,
        y: canvasSize.height / 2 - 70,
        width: 10,
        height: 140,
        score: 0,
        color: player1?.paddle_color || '#FFFFFF',
    });

    const user2Ref = useRef({
        x: canvasSize.width - 30,
        y: canvasSize.height / 2 - 70,
        width: 10,
        height: 140,
        score: 0,
        color: player2?.paddle_color || '#3357FF',
    });

    const ballRef = useRef({
        x: canvasSize.width / 2,
        y: canvasSize.height / 2,
        radius: 10,
        velocityX: 5,
        velocityY: 5,
        speed: 7,
        color: "WHITE"
    });

    const calculateCanvasSize = useCallback(() => {
        const containerWidth = window.innerWidth * 0.8;
        const containerHeight = window.innerHeight * 0.7;
        const aspectRatio = 16 / 9;

        let newWidth, newHeight;

        if (containerWidth / containerHeight > aspectRatio) {
            newHeight = containerHeight;
            newWidth = newHeight * aspectRatio;
        } else {
            newWidth = containerWidth;
            newHeight = newWidth / aspectRatio;
        }

        setCanvasSize({ width: Math.floor(newWidth), height: Math.floor(newHeight) });
    }, []);

    const scaleFactor = useCallback(() => {
        return {
            x: canvasSize.width / 1384,
            y: canvasSize.height / 696
        };
    }, [canvasSize]);

    useEffect(() => {
        calculateCanvasSize();
        const debouncedResizeHandler = debounce(calculateCanvasSize, 250);
        window.addEventListener('resize', debouncedResizeHandler);
        return () => window.removeEventListener('resize', debouncedResizeHandler);
    }, [calculateCanvasSize]);

    useEffect(() => {
        if (player1 && player2) {
            user1Ref.current.color = player1.paddle_color;
            user2Ref.current.color = player2.paddle_color;
            setShowAboutGame(true);
        }
    }, [player1, player2]);

    useEffect(() => {
        if (!canvasRef.current || !matchRunning) return;

        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        const user1 = user1Ref.current;
        const user2 = user2Ref.current;
        const ball = ballRef.current;

        canvas.width = canvasSize.width;
        canvas.height = canvasSize.height;

        const scale = scaleFactor();

        function handleKeyDown(evt) {
            if (['ArrowUp', 'ArrowDown', 'w', 's'].includes(evt.key)) {
                setKeyState(prev => ({ ...prev, [evt.key]: true }));
            }
        }

        function handleKeyUp(evt) {
            if (['ArrowUp', 'ArrowDown', 'w', 's'].includes(evt.key)) {
                setKeyState(prev => ({ ...prev, [evt.key]: false }));
            }
        }

        window.addEventListener('keydown', handleKeyDown);
        window.addEventListener('keyup', handleKeyUp);
        function movePaddles() {
            const moveDistance = 5;
            const maxY = canvas.height / scale.y - user1.height;
        
            function moveUp(user) {
                user.y = Math.max(0, user.y - moveDistance);
            }
        
            function moveDown(user) {
                user.y = Math.min(maxY, user.y + moveDistance);
            }
        
            if (player1.keys === 'ws') {
                if (keyState.ArrowUp) moveUp(user1);
                if (keyState.ArrowDown) moveDown(user1);
                if (keyState.w) moveUp(user2);
                if (keyState.s) moveDown(user2);
            } else {
                if (keyState.w) moveUp(user1);
                if (keyState.s) moveDown(user1);
                if (keyState.ArrowUp) moveUp(user2);
                if (keyState.ArrowDown) moveDown(user2);
            }
        }

        function resetBall() {
            ball.x = canvas.width / (2 * scale.x);
            ball.y = canvas.height / (2 * scale.y);
            ball.velocityX = -ball.velocityX;
            ball.speed = 7;
        }

        function collision(b, p) {
            const pScaled = {
                top: p.y * scale.y,
                bottom: (p.y + p.height) * scale.y,
                left: p.x * scale.x,
                right: (p.x + p.width) * scale.x,
            };

            const bScaled = {
                top: (b.y - b.radius) * scale.y,
                bottom: (b.y + b.radius) * scale.y,
                left: (b.x - b.radius) * scale.x,
                right: (b.x + b.radius) * scale.x,
            };

            return pScaled.left < bScaled.right && pScaled.top < bScaled.bottom && pScaled.right > bScaled.left && pScaled.bottom > bScaled.top;
        }

        function update() {
            movePaddles();

            ball.x += ball.velocityX;
            ball.y += ball.velocityY;
            
            if (ball.y - ball.radius < 0 || ball.y + ball.radius > canvas.height / scale.y) {
                ball.velocityY = -ball.velocityY;
            }
            
            const player = (ball.x < canvas.width / (2 * scale.x)) ? user1 : user2;
            if (collision(ball, player)) {
                let collidePoint = (ball.y - (player.y + player.height / 2)) / (player.height / 2);
                let angleRad = (Math.PI / 4) * collidePoint;
                let direction = (ball.x < canvas.width / (2 * scale.x)) ? 1 : -1;
                ball.velocityX = direction * ball.speed * Math.cos(angleRad);
                ball.velocityY = ball.speed * Math.sin(angleRad);
                ball.speed += 0.1;
            }

            if (ball.x - ball.radius < 0) {
                user2.score++;
                setUser2Score(user2.score);
                resetBall();
            } else if (ball.x + ball.radius > canvas.width / scale.x) {
                user1.score++;
                setUser1Score(user1.score);
                resetBall();
            }
        }
    
        const drawRoundedRect = (x, y, width, height, radius) => {
            ctx.beginPath();
            ctx.moveTo((x + radius) * scale.x, y * scale.y);
            ctx.arcTo((x + width) * scale.x, y * scale.y, (x + width) * scale.x, (y + height) * scale.y, radius * Math.min(scale.x, scale.y));
            ctx.arcTo((x + width) * scale.x, (y + height) * scale.y, x * scale.x, (y + height) * scale.y, radius * Math.min(scale.x, scale.y));
            ctx.arcTo(x * scale.x, (y + height) * scale.y, x * scale.x, y * scale.y, radius * Math.min(scale.x, scale.y));
            ctx.arcTo(x * scale.x, y * scale.y, (x + width) * scale.x, y * scale.y, radius * Math.min(scale.x, scale.y));
            ctx.closePath();
            ctx.fill();
        };
        
        function render() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = 'rgba(22, 22, 37, 0.9)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
        
            const netWidth = 2;
            const netX = canvas.width / 2 - netWidth / 2;
            ctx.fillStyle = "#2C3143";
            for (let i = 0; i <= canvas.height; i ++) {
                ctx.fillRect(netX, i, netWidth, 10);
            }
            ctx.fillStyle = user1.color;
            drawRoundedRect(user1.x, user1.y, user1.width, user1.height, 5);
        
            ctx.fillStyle = user2.color;
            drawRoundedRect(user2.x, user2.y, user2.width, user2.height, 5);
            ctx.beginPath();
            ctx.arc(ball.x * scale.x, ball.y * scale.y, ball.radius * Math.min(scale.x, scale.y), 0, Math.PI * 2);
            ctx.fillStyle = ball.color;
            ctx.fill();
            ctx.closePath();
        }

        let animationId;
        function gameLoop() {
            update();
            render();
            animationId = requestAnimationFrame(gameLoop);
        }

        gameLoop();

        return () => {
            window.removeEventListener('keydown', handleKeyDown);
            window.removeEventListener('keyup', handleKeyUp);
            cancelAnimationFrame(animationId);
        };
    }, [matchRunning, canvasSize, scaleFactor, keyState]);

    useEffect(() => {
        const WINNING_SCORE = 2
        if (user1Score === WINNING_SCORE || user2Score === WINNING_SCORE) {
            const winner = user1Score > user2Score ? player1?.username : player2?.username;
            const loser = user1Score > user2Score ? player2?.username : player1?.username;
            handleEndMatch(winner, loser);
            setMatchRunning(false);
            setGameOver(true);
        }
    }, [user1Score, user2Score]);

    if (gameOver) {
        return null;
    }
    
    if (isLoadingPlayer1 || isLoadingPlayer2) {
        return <div><Loading/></div>;
    }
    
    if (player1Error || player2Error) {
        return <div>Error loading players</div>;
    }

    const handleStartGame = () => {
        setShowAboutGame(false);
        setMatchRunning(true);
    };

    return (
        <div className="pingponggame-container">
            {matchRunning && (
                <>
                    <div className="info-container">
                        {player1 && player2 ? (
                            <ScoreBoard
                                user1Score={user1Score}
                                user2Score={user2Score}
                                user1={player1}
                                user2={player2}
                            />
                        ) : (
                            <div>LOADING PLAYERS</div>
                        )}
                    </div>
                    <canvas className='canvas-container' ref={canvasRef}></canvas>
                </>
            )}
    
            {showAboutGame && (
                <AboutLocalGame 
                    player1={player1} 
                    player2={player2} 
                    handleStartGame={handleStartGame}
                />
            )}
        </div>
    );
};

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

export default LocalGameLogic;