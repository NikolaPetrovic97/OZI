
 #   H i b r i d n a   k r i p t o g r a f i j a 
 A s i m e t r i n i   i   s i m e t r i n i   k r i p t o   s i s t e m i   z a j e d n o   o b e z b e u j u   s i g u r n o s t   p r e n o s a   p o d a t a k a   p r e k o   n e s i g u r n o g   m e d i j a .   R a d i   u   d v e   f a z e ,   u   p r v o j   f a z i   k l j u   z a   ai f r i r a n j e   /   d e ai f r o v a n j e   i n f o r m a c i j a   d e l i   s e   p o m o c u   R S A   k l j u n i h   p a r o v a   ( A s i m m e t r i c   C r i p t o ) .   N a k o n   z a v r ae t k a   p r v e   f a z e ,   k o m u n i k a c i j a   s e   d e aa v a   u   d r u g o j   f a z i   u   k o j o j   s u   i n f o r m a c i j e   ai f r i r a n e   /   d e k r i p t i r a n e   p o m o c u   A E S   s i m e t r i n i h   k l j u e v a   ( s i g u r n o   d e l e   u   p r v o j   f a z i ) . 
 
 # #   P o k r e t a n j e   p r o g r a m a :   ( N a   l o c a l h o s t ) 
 
 S v e   ae s t   f a j l o v a   ( e t i r i   k l a s e   i   d v e   k l j u n e   d a t o t e k e )   t r e b a   s a u v a t i   u   i s t o m   d i r e k t o r i j u m u . 
 
 Z a   s i m u l i r a n j e   m o d e l a   k l i j e n t s k o g   s e r v e r a   p o t r e b n i   s u   d v a   t e r m i n a l n a   p r o z o r a . 
 
 U   p r v o m   p r o z o r u   t e r m i n a l a :   P o k r e n i t e   s e r v e r s k i   p r o g r a m   -   $   j a v a   S e r v e r 
 U   d r u g o m   t e r m i n a l u :   P o k r e n i t e   p r o g r a m   k l i j e n t a   -   $   j a v a   C l i e n t 
 
 
 # # #   K l j u n e   f u n k c i j e   k o j e   s e   k o r i s t e : 
 
 -   j a v a   u m r e ~a v a n j e   k l i j e n t s k i h   i   s e r v e r s k i h   u t i n i c a 
 -   N i t i . 
 -   J a v a   S e r i a l i z a c i j a . 
 -   J a v a   a r h i t e k t u r a   k r i p t o g r a f i j e 
 
 # # #   S i g u r n o s n i   a l g o r i t m i : 
 R S A   i   A E S 
 
 
 D o k a z   o   a p l i k a c i j i   k o n c e p t a   s a s t o j i   s e   o d   e t i r i   J a v a   k l a s e : 
 
 1 .   S e r v e r . j a v a 
 2 .   C l i e n t . j a v a 
 3 .   m e s s a g e . j a v a 
 4 .   R S A . j a v a 
 
 
 K o m p i l a c i j a :   K l a s i   s e r v e r a   i   k l i j e n t a   j e   p o t r e b n a   k o m p i l a c i j a . 
 
 K a d a   s e   p r o g r a m   C l i e n t   p o k r e n e ,   p r v a   f a z a   d e l j e n j a   k l j u a   s e   o d v i j a   a u t o m a t s k i . 
 
 N a k o n   p r v e   f a z e ,   i   k l i j e n t   i   s e r v e r   m o g u   s l a t i   i   p r i m a t i   p o r u k e . 
 
 
 
 I M P : 
 
 1 .   D v a   k l j u n a   f a j l a   -   p u b l i c . k e i   i   p r i v a t e . k e i   m o r a j u   b i t i   u   i s t o m   d i r e k t o r i j u m u . 
 2 .   P o r t   8 0 0 2   b i   t r e b a l o   s l o b o d n o   d a   k o r i s t i   o v u   a p l i k a c i j u . 
 3 .   A k o   j e   p o t r e b a n   n o v i   k a i   p a r ,   s a m o   k o m p a j l i r a j t e   i   p o k r e n i t e   R S A . j a v a .   K r e i r a c e   d v e   n o v e   d a t o t e k e . 
 
 
 # # # # # # # # # # # # # #   D a   b i s t e   p o k r e n u l i   k l i j e n t   i   s e r v e r   n a   r a z l i i t i m   m a ai n a m a 
 
 P o t r e b n e   d a t o t e k e   n a   k l i j e n t s k o j   m a ai n i   ( u   i s t o m   d i r e k t o r i j u m u ) : 
 1 .   C l i e n t . j a v a 
 2 .   m e s s a g e . j a v a 
 3 .   p u b l i c . k e i 
 4 .   p r i v a t e . k e i 
 
 U p o t r e b a :   $   j a v a   C l i e n t   [ s e r v e r   I P ] 
 
 
 P o t r e b n e   d a t o t e k e   n a   k l i j e n t s k o j   m a ai n i   ( u   i s t o m   d i r e k t o r i j u m u ) : 
 1 .   S e r v e r . j a v a 
 2 .   m e s s a g e . j a v a 
 3 .   p u b l i c . k e i 
 4 .   p r i v a t e . k e i 
 
 U p o t r e b a :   $   j a v a   s e r v e r 
 
 
 